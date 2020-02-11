import glob
import os
from colorama import Fore
import html
import yara

from slacksecrets.utils import info, warning


def build_rules_filepaths(rules_dirs):
    filepaths = {}
    for rules_dir in rules_dirs:
        for path in glob.glob('{}/*.yar'.format(rules_dir)):
            filepaths[os.path.basename(path).replace('.yar', '')] = path
    return filepaths


class Secrets:
    """
    Class to hold the rules, scanning functionality, etc.
    yara-python is imported as `yara` so wanted a different class name.
    """
    def __init__(self, rule_dirs=None, default_externals=None, reporting_callback=None):
        if rule_dirs is None:
            rule_dirs = []
        elif isinstance(rule_dirs, str):
            rule_dirs = [rule_dirs]

        if default_externals is None:
            default_externals = {'filename': ''}

        if reporting_callback is None:
            reporting_callback = self.print_terminal_reporting_callback

        self.default_externals = default_externals
        self.rules_dirs = rule_dirs
        self.reporting_callback = reporting_callback

        # compile the YARA rules so we can use them for matches
        rules_filepaths = build_rules_filepaths(self.rules_dirs)
        rule_count = len(rules_filepaths.keys())
        if rule_count > 0:
            info("Compiled {} rules".format(rule_count))
        else:
            warning("Compiled {} rules".format(rule_count))
        self.compiled_rules = yara.compile(filepaths=rules_filepaths, externals=self.default_externals)

    def scan_message(self, message):
        # We need to report back the full contents of a message (so we can preserve the context of the matched string).
        # So we'll generate a callback function that already has the message object passed along.
        def generate_callback(msg):
            def message_match_callback(yara_match_data):
                for match in yara_match_data.get('strings'):
                    # This is where the reporting happens. `reporting_callback` is configurable. If no callback
                    # has been configured, then `print_terminal_reporting_callback` will be used.
                    self.reporting_callback(msg, yara_match_data.get('rule'), match[2].decode())

                # Signal to YARA to continue running additional match checks on the message.
                # A single post/message may contain several different types of secrets, for example,
                # if the message contains configuration information.
                return yara.CALLBACK_CONTINUE

            return message_match_callback

        # With the callback containing the full messaged generated, we can now run the YARA rules against
        # the message. Note here that `generate_callback(message)` will return a `message_match_callback` method
        # which YARA will pass the matching data. That method will call whichever reporting callback was configured.
        self.compiled_rules.match(
            data=message.get('text'),
            externals=self.default_externals,
            callback=generate_callback(message),
            which_callbacks=yara.CALLBACK_MATCHES)

    @classmethod
    def print_terminal_reporting_callback(self, message, rule, matching_str):
        """
        The default reporting callback for rule matches will simply print the match to the screen.
        While the color currently used is green, there is no red involved, and the text is also set to "bright" which
        is how Colorama essentially declares "bold"/"strong", so we _should_ be ok with accessibility / a11y concerns
        in terms of differentiating text, but would like feedback.
        """
        from colorama import Style
        formatted_text = message.get('text', '').replace(matching_str, Fore.GREEN + Style.BRIGHT + matching_str + Style.RESET_ALL)
        print("[{}:{}] {}\t{}".format(message.get('channel', ''), message.get('ts', ''), rule, html.unescape(formatted_text)))
