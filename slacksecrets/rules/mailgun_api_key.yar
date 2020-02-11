rule MailgunApiKeyRule
{
    meta:
        name = "Mailgun API Key"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "key-123456789012345678901234AbcDEfGH"

    strings:
        $ = /key-[0-9a-zA-Z]{32}/ fullword

    condition:
        any of them
}