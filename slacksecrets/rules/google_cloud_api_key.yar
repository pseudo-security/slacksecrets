rule GoogleCloudApiKeyRule : Google
{
    meta:
        name = "Google Cloud API Keys"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "AIzaGoogleCloudAPIKeyAazZ09780w00tTests"

    strings:
        $ = /AIza[0-9A-Za-z-_]{35}/ fullword

    condition:
        any of them
}