import time
import slack
from pony.orm import commit, db_session
from slack.errors import SlackApiError
from slack.web.slack_response import SlackResponse

from slacksecrets.utils import warning, info
from slacksecrets.models import Conversation, User, Finding


class SlackWrapper:
    """
    SlackWrapper abstracts the Slack client to just what is needed for SlackSecrets.
    This includes hooking into the real-time messaging API, handling rate-limiting
    """

    def __init__(self, token: str):
        self.token = token
        self.wc = slack.WebClient(token=token)

    @staticmethod
    def iter_rate(response: SlackResponse):
        """
        Rate-limited aware iterator generator ... iterator rate ... iter rate.
        Puns are important in life.
        """

        # SlackResponse needs to initialize the internal iterator count and initial data
        response.__iter__()

        while True:
            try:
                yield next(response)
            except StopIteration:
                # Reached the end of the Slack data, time to end the loop
                break
            except SlackApiError as ex:
                # According to the internals of SlackResponse, the internal data and iterator counter
                # will not be updated if the reaponse._client._request raises an exception. Thus, it should
                # be possible to just wait the required cool-off period and the next iteration of the loop
                # should still be at the same spot.
                if ex.response.status_code == 429 and "Retry-After" in ex.response.headers:
                    # If Slack is rate-limiting our calls, wait the required time
                    wait_period = float(ex.response.headers["Retry-After"])
                    warning("Rate limited, waiting for {}s".format(wait_period))
                    time.sleep(wait_period)
                else:
                    # Only suppress the SlackApiError when we're rate-limited
                    raise

    @property
    def is_free_plan(self):
        try:
            self.wc.team_accessLogs()
            return True
        except SlackApiError as ex:
            return ex.response.data['ok'] is False and ex.response.data['error'] == "paid_only"
        except Exception:
            return False

    def generate_db_name(self):
        try:
            return self.wc.auth_test().data['team'].lower()
        except Exception:
            return 'slacksecrets'

    def get_users(self):
        users = []
        response = self.wc.users_list()
        # SlackResponse has an __iter__ method that handles pagination
        # so we can leverage that and be lazy.
        for data in self.iter_rate(response):
            for member in data.get('members', []):
                users.append(member)

        return users

    def get_convos(self):
        convos = []
        response = self.wc.conversations_list(types="public_channel, private_channel, mpim, im")
        # SlackResponse has an __iter__ method that handles pagination
        # so we can leverage that and be lazy.
        for data in self.iter_rate(response):
            # The Slack API is still mixing and matching legacy naming of channels, IMs, etc.
            # with the more recent switch to `conversations` so despite calling a `conversation_list` API,
            # we need to extract the `channels` field from the returned data structure.
            for convo in data.get('channels', []):
                # raise SlackApiError(message=msg, response=self)
                convos.append(convo)

        return convos

    def get_permalink(self, channel, ts):
        return self.wc.chat_getPermalink(channel=channel, message_ts=ts)['permalink']

    def process_convo_history(self, conversation_id: int, message_callback_fn=None):
        with db_session:
            conversation = Conversation[conversation_id]

            # use the provided most-recently scanned timestamp, otherwise default to channel creation timestamp.
            latest_ts = conversation.latest_ts if (float('0' + conversation.latest_ts) > 0) else conversation.created
            response = self.wc.conversations_history(
                channel=conversation.id,
                oldest=latest_ts,
            )

            for data in self.iter_rate(response):
                # When searching from oldest to newest (paging forward in time),
                # Slack will have the oldest message at the end of the list, so we
                # reverse the list so every message is in correct chronological order.
                sorted_messages = reversed(data.get('messages', []))
                for message in sorted_messages:
                    # Slack is weird in that not every message will have a channel id attached to the message object,
                    # so we manually add it in case there is a secret that needs to be reported - the channel ID will
                    # be needed.
                    message['channel'] = conversation.id

                    # Hand-off the message to the processing callback function
                    message_callback_fn(message)

                    # After the message has been processed we need to update the latest timestamp scanned.
                    # Exiting the db_session context will call commit() and ensure database has the latest ts saved.
                    conversation.latest_ts = message['ts']
                    conversation.messages_processed += 1

                # commit() is called automatically when the db_session ends, but we want to ensure after every
                # reponse from Slack is done being processed, that the progress is saved in the database.
                commit()

        # Sometimes I've seen the automatic commit() fail to be called so just do it again to be sure
        commit()
