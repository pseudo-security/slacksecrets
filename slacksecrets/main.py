import glob
import json
import os
import pkg_resources
import slack
from colorama import Style
from pony.orm import commit, db_session
from tqdm import tqdm

from slacksecrets.utils import dump_config, error, info
from slacksecrets.models import Conversation, Finding, User, db
from slacksecrets.secrets import Secrets
from slacksecrets.slackwrapper import SlackWrapper


class SlackSecrets:
    def __init__(self, args):
        self.args = args

    def init(self):
        self.slacker = SlackWrapper(self.args['token'])

        info("Initializing secrets engine")

        self.secrets = Secrets(
            rule_dirs=pkg_resources.resource_filename('slacksecrets', 'rules'),
            reporting_callback=self.report_match)

        self.args['db-name'] = "%s.db" % self.slacker.generate_db_name()
        self.args['is-free'] = self.slacker.is_free_plan

        dump_config(self.args)

        db_abs_path = os.path.join(self.args.get('db-path'), self.args.get('db-name'))
        db.bind(provider='sqlite', filename=db_abs_path, create_db=True)
        db.generate_mapping(create_tables=True)

        if not self.args.get('skip_db_update', False):
            self.update_db()

    def reset(self):
        for convo in self.slacker.get_convos():
            with db_session:
                c = Conversation[convo['id']]
                c.scanned_ranges = []
                c.messages_processed = 0
                c.reached_end = False
                c.lastest_ts = ''
            commit()

    def live_monitor(self):
        info("Starting Real-Time Message monitoring")
        rtm_client = slack.RTMClient(token=self.args.get('token'))
        rtm_client.start()

    def exported(self):
        # TODO: this function is pretty sloppy and should be refactored
        info("Starting Real-Time Message monitoring")

        users_json = os.path.join(self.args.get('exported_dir'), 'users.json')
        channels_json = os.path.join(self.args.get('exported_dir'), 'channels.json')

        if not os.path.exists(users_json) or not os.path.exists(channels_json):
            error("users.json or channels.json does not exist in directory: {}".format(self.args.get('exported_dir')))
            return

        with db_session:
            with open(users_json, 'r') as fp:
                for user in json.load(fp):
                    if User.select(lambda u: u.id == user.get('id')).count() == 0:
                        User.from_dict(user)
            with open(channels_json, 'r') as fp:
                for convo in json.load(fp):
                    if Conversation.select(lambda c: c.id == convo.get('id')).count() == 0:
                        Conversation.from_dict(convo)

            from os import listdir
            from os.path import isfile, join
            onlydirs = [f for f in listdir(self.args.get('exported_dir')) if not isfile(join(self.args.get('exported_dir'), f))]
            for dir in onlydirs:

                res = Conversation.select(lambda c: dir == c.name)
                if res.count() == 1:
                    channel = res.first().id
                elif Conversation.select(lambda c: dir == c.id).count() == 1:
                    channel = dir
                else:
                    error("Cant determine channel/conversation id for exported directory: {}".format(dir))
                    continue

                json_files = glob.glob(os.path.join(self.args.get('exported_dir'), dir, '*.json'))

                pbar = tqdm(total=len(json_files), unit="day", unit_divisor=1)
                pbar.set_description(Style.RESET_ALL + "[ ] {}".format(dir))
                for file in json_files:
                    with open(file, 'rb') as json_fp:
                        for message in json.load(json_fp):
                            message['channel'] = channel
                            self.secrets.scan_message(message)
                    pbar.update(1)
                pbar.close()

    def history(self):
        info("Starting historical conversation scanning")
        convos = self.slacker.get_convos()

        pbar = tqdm(total=len(convos), unit="channel", unit_divisor=1)
        for convo in convos:
            convo_name = convo['name'] if 'name' in convo and convo['name'] is not None else convo['id']
            pbar.set_description(Style.RESET_ALL + "[ ] {}".format(convo_name))
            self.slacker.process_convo_history(convo['id'], self.secrets.scan_message)
            pbar.update(1)
        pbar.close()

    def report_match(self, message, rule_id, matching_text):
        # To get a permalink to this message, we need the channel and event timestamp.
        # We cannot construct the permalink manually since if the message is part of a message-thread,
        # then the format of the permalink changes (https://api.slack.com/methods/chat.getPermalink).
        # We could call out to the Slack API but that will cause delay with a network request, and it's
        # in the current event loop. While async is possible, it's just easier to log the channel and event_ts
        # and then populate the permalink later.

        with db_session:
            if Finding.select(
                    lambda f:
                    f.channel == message.get('channel') and
                    f.ts == message.get('ts') and
                    f.rule_id == rule_id and
                    f.matching_text == matching_text
            ).count() == 0:
                Finding(
                    channel=message.get('channel'),
                    ts=message.get('ts'),
                    rule_id=rule_id,
                    matching_text=matching_text,
                    full_text=message.get('text'),
                    permalink=''
                )
                commit()

        # Call the default reporting callback which is just glorified print-to-terminal
        self.secrets.print_terminal_reporting_callback(message, rule_id, matching_text)

    def process_rtm_file_created(self, payload):
        # TODO: implement file upload checks. There needs to be a balance between matching on files,
        # and actually inspecting their contents. Most likely this should be a configurable setting,
        # as the user may want to download/preserve the uploaded files that have been scanned/match,
        # though we'll still preserve the file id and matching text anyway. The overall issue will be a storage
        # directory and ensuring enough space. Slack will tell us how large the file is, so we can prevent downloads
        # and warn the user when running out of disk space ... but that's going to take
        file_id = payload.get('data', {}).get('file_id', None)
        pass

    def process_rtm_message(self, payload):
        # Perform a secrets search on text field. There is also a 'blocks' field which is used by Slack
        # for visually rendering the message, but we're only concerned with the plain-text.
        data = payload.get('data', {})
        if 'text' not in data:
            return

        self.secrets.scan_message(data)

    def update_db(self):
        with db_session:
            info("Updating Users in database")
            for user in self.slacker.get_users():
                if User.select(lambda u: u.id == user.get('id')).count() == 0:
                    User.from_dict(user)

            info("Updating Conversations/Channels in database")
            for convo in self.slacker.get_convos():
                if Conversation.select(lambda c: c.id == convo.get('id')).count() == 0:
                    Conversation.from_dict(convo)

            info("Updating Finding permalinks in database")
            findings = Finding.select(lambda f: f.permalink == '')
            for finding in findings:
                finding.permalink = self.slacker.get_permalink(finding.channel, finding.ts)
        commit()
