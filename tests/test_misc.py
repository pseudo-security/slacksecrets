from slacksecrets.utils import mask_slack_token


def test_token_masking():
    token = "xoxp-111111111111-22222222222-333333333333-444444444444444444444444abcdefgh"
    masked = ''.join('*' if c.isdigit() else c for c in token)
    assert (mask_slack_token(token) == masked)
