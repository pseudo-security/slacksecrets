import argparse
import os
import slack

from slacksecrets.utils import banner, error
from slacksecrets.main import SlackSecrets


def build_parsers():
    parser = argparse.ArgumentParser()

    base_parser = argparse.ArgumentParser(add_help=False)
    base_parser.add_argument('--token', default=os.getenv('SLACK_TOKEN'))
    base_parser.add_argument('--no-banner', action='store_true')
    base_parser.add_argument('--skip-db-update', action='store_true')

    subparsers = parser.add_subparsers(title='subcommands', dest='mode', description='valid subcommands')
    subparsers.add_parser('live', help='Live help', parents=[base_parser])
    subparsers.add_parser('history', help='Live help', parents=[base_parser])
    subparsers.add_parser('reset', help='Reset help', parents=[base_parser])
    subparsers.add_parser('files', help='Files help', parents=[base_parser]) \
        .add_argument('--tesseract-dir')
    subparsers.add_parser('exported', help='Exported help', parents=[base_parser]) \
        .add_argument('--exported-dir', required=True)

    return parser


def main():

    parser = build_parsers()
    args = parser.parse_args()

    if args.token is None or args.token == '':
        error("Missing Slack token, cannot continue")
        exit(1)

    if args.mode == 'exported':
        if args.exported_dir is None:
            error("Export mode requires a valid directory")
            exit(1)
        args.exported_dir = os.path.abspath(args.exported_dir)

    args.db_path = os.path.abspath(os.path.curdir)

    if not args.no_banner:
        banner()

    slacksecrets = SlackSecrets(vars(args))
    slacksecrets.init()

    # subscribe to all file creation events
    @slack.RTMClient.run_on(event='file_created')
    def process_rtm_file_created(**payload):
        slacksecrets.process_rtm_file_created(payload)

    # subscribe to all message events
    @slack.RTMClient.run_on(event='message')
    def process_rtm_message(**payload):
        slacksecrets.process_rtm_message(payload)

    if args.mode == 'live':
        slacksecrets.live()
    elif args.mode == 'history':
        slacksecrets.history()
    elif args.mode == 'exported':
        slacksecrets.exported()
    elif args.mode == 'reset':
        slacksecrets.reset()
    elif args.mode == 'files':
        slacksecrets.files()
    else:
        parser.print_usage()


if __name__ == "__main__":
    main()
