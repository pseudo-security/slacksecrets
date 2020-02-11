rule TwilioApiKeyRule
{
    meta:
        name = "Twilio API Key"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "55123456789012345678901234F00Df00d"
        test_no_match_1 = "551234567ZZ012345678901234FzzDf00d"

    strings:
        $ = /55[0-9a-fA-F]{32}/

    condition:
        any of them
}