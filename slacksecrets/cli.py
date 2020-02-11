import argparse
import os
import slack

from slacksecrets.utils import banner, error
from slacksecrets.main import SlackSecrets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['live', 'history', 'exported', 'reset'])
    parser.add_argument('--token')
    parser.add_argument('--no-banner', action='store_true')
    parser.add_argument('--skip-db-update', action='store_true')
    parser.add_argument('--exported-dir')

    args = parser.parse_args()
    final_args = {k: v for k, v in vars(args).items() if v is not None}
    final_args['token'] = final_args.get('token', os.getenv('SLACK_TOKEN', ''))
    if final_args.get('token', '') == '':
        error("Missing Slack token, cannot continue")
        exit(1)

    if final_args.get('exported_dir') is not None:
        final_args['exported_dir'] = os.path.abspath(final_args.get('exported_dir'))
    final_args['db-path'] = os.path.abspath(os.path.curdir)

    if not final_args.get('no_banner', False):
        banner()

    slacksecrets = SlackSecrets(final_args)
    slacksecrets.init()

    # subscribe to all file creation events
    @slack.RTMClient.run_on(event='file_created')
    def process_rtm_file_created(**payload):
        slacksecrets.process_rtm_file_created(payload)

    # subscribe to all message events
    @slack.RTMClient.run_on(event='message')
    def process_rtm_message(**payload):
        slacksecrets.process_rtm_message(payload)

    mode = final_args.get('mode')
    if mode == 'live':
        slacksecrets.live_monitor()
    elif mode == 'history':
        slacksecrets.history()
    elif mode == 'exported' and final_args.get('exported_dir') is not None:
        slacksecrets.exported()
    elif mode == 'reset':
        slacksecrets.reset()
    else:
        parser.print_usage()


if __name__ == "__main__":
    main()
