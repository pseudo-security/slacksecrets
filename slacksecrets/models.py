from pony.orm import Database, Json, Optional, PrimaryKey, Required

# Need to declare a database instance so that our models can inherit from the Entity class
# of this
db = Database()


class Conversation(db.Entity):
    """
    https://api.slack.com/types/conversation
    """
    id = PrimaryKey(str, auto=False)
    name = Optional(str)
    normalized_name = Optional(str)
    purpose = Optional(str)
    is_channel = Optional(bool)
    is_im = Optional(bool)
    is_archived = Optional(bool)
    is_general = Optional(bool)
    is_shared = Optional(bool)
    is_member = Optional(bool)
    is_private = Optional(bool)
    is_mpim = Optional(bool)
    created = Required(int)
    scanned_ranges = Optional(Json, default=[])
    messages_processed = Required(int)
    reached_end = Required(bool, default=False)
    latest_ts = Optional(str)
    reached_now = Optional(bool, default=False)

    @staticmethod
    def from_dict(convo):
        Conversation(
            id=convo.get('id'),
            name=convo.get('name', 'N/A'),
            normalized_name=convo.get('normalized_name', 'N/A'),
            purpose=convo.get('purpose', {}).get('value', ''),
            is_channel=convo.get('is_channel', False),
            is_im=convo.get('is_im', False),
            is_archived=convo.get('is_archived', False),
            is_general=convo.get('is_general', False),
            is_shared=convo.get('is_shared', False),
            is_member=convo.get('is_member', False),
            is_private=convo.get('is_private', False),
            is_mpim=convo.get('pyis_mpim', False),
            created=int(convo.get('created')),
            scanned_ranges=convo.get('scanned_ranges', []),
            messages_processed=int(convo.get('messages_processed', 0)),
            reached_end=convo.get('reached_end', False),
            reached_now=convo.get('reached_now', False),
            latest_ts=convo.get('latest_ts', '')
        )


class User(db.Entity):
    """
    https://api.slack.com/types/user
    """
    id = PrimaryKey(str, auto=False)
    name = Required(str)
    real_name = Optional(str)
    real_name_normalized = Optional(str)
    display_name = Optional(str)
    display_name_normalized = Optional(str)
    first_name = Optional(str)
    last_name = Optional(str)
    is_admin = Required(bool)
    is_owner = Required(bool)
    is_primary_owner = Required(bool)
    is_restricted = Required(bool)
    is_ultra_restricted = Required(bool)
    is_bot = Required(bool)
    is_app_user = Required(bool)
    has_2fa = Required(bool)

    @staticmethod
    def from_dict(user):
        User(
            id=user.get('id'),
            name=user.get('name', 'N/A'),
            real_name=user.get('real_name', ''),
            real_name_normalized=user.get('real_name_normalized', ''),
            display_name=user.get('display_name', ''),
            display_name_normalized=user.get('display_name_normalized', ''),
            first_name=user.get('first_name', ''),
            last_name=user.get('last_name', ''),
            is_admin=user.get('is_admin', False),
            is_owner=user.get('is_owner', False),
            is_primary_owner=user.get('is_primary_owner', False),
            is_restricted=user.get('is_restricted', False),
            is_ultra_restricted=user.get('is_ultra_restricted', False),
            is_bot=user.get('is_bot', False),
            is_app_user=user.get('is_app_user', False),
            has_2fa=user.get('has_2fa', False),
        )


class File(db.Entity):
    """
    https://api.slack.com/types/file
    """
    id = PrimaryKey(str, auto=False)
    size = Required(int)
    ts = Required(int)  # created field in Slack's file object

    name = Required(str)
    title = Required(str)
    mimetype = Required(str)
    filetype = Required(str)
    user = Required(str)
    mode = Required(str)
    is_external = Required(bool)
    is_public = Required(bool)
    public_url_shared = Required(bool)

    url_private = Required(str)
    permalink = Required(str)

    model = """
        "size": 144538,
        "created": 1531763342,
        "name": "billair.gif",
        "title": "billair.gif",
        "mimetype": "image/gif",
        "filetype": "gif",
        "user": "U061F7AUR",
        "mode": "hosted",
        "is_external": false,
        "is_public": true,
        "public_url_shared": false,
        
        "editable": false,
        "external_type": "",
        "display_as_bot": false,
        "username": "",
        "url_private": "https://.../billair.gif",
        "url_private_download": "https://.../billair.gif",
        "deanimate_gif": "https://.../billair_deanimate_gif.png",
        "pjpeg": "https://.../billair_pjpeg.jpg",
        "permalink": "https://https://.../billair.gif",
        "permalink_public": "https://.../...",
        
        
        "thumb_64": "https://.../billair_64.png",
        "thumb_80": "https://.../billair_80.png",
        "thumb_360": "https://.../billair_360.png",
        "thumb_360_w": 176,
        "thumb_360_h": 226,
        "thumb_160": "https://.../billair_=_160.png",
        "thumb_360_gif": "https://.../billair_360.gif",
        "image_exif_rotation": 1,
        "original_w": 176,
        "original_h": 226,
"""


class Finding(db.Entity):
    # The primary-key for a match is the channel + timestamp, the rule identifier,
    # and the matching string. This way we will know if a single string matched to more than one rule in a message,
    # and if the same string is in a message 100 times, it's only recorded once.
    #
    # Ideally we would have used client_msg_id but it is not available for all messages it seems, and according
    # to Slack's documentation, the ts field should be per-channel unique. Because the database is constrained to
    # a single instance/workspace, channel + ts should get us a unique message id, and then we just need to add on
    # the rule and matching string for the fully unique id for the Finding entry. An option would have been to discard
    # the channel + ts and only store the permalink, but that'd require querying Slack's API every time a match was
    # found, and that'd slow down the scanning to some degree. The permalink is hydrated later from the channel + ts.
    #
    # https://api.slack.com/messaging/retrieving
    # > The ts value is essentially the ID of the message,
    # > guaranteed unique within the context of a channel or conversation.
    channel = Required(str)
    ts = Required(str)
    rule_id = Required(str)
    matching_text = Required(str)

    PrimaryKey(channel, ts, rule_id, matching_text)

    # used to provide context for the match
    full_text = Required(str)

    # permalink for easy deep-linking later
    permalink = Optional(str)

    @staticmethod
    def from_dict(finding):
        Finding(
            channel=finding.get('channel'),
            ts=finding.get('ts'),
            rule_id=finding.get('rule_id'),
            matching_text=finding.get('matching_text'),
            full_text=finding.get('full_text'),
            permalink=finding.get('permalink', ''),
        )
