rule GenericPasswordRule
{
    meta:
        name = "Generic Password"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "secret_password = 'this is a secret'"
        test_match_2 = "secret_password: this is a secret"
        test_no_match = "At the next meeting we'll discuss our password policies."

    strings:
        $quoted = /("|')password(("|')\s*(:|=>|=)\s*("|'))(.*)("|')/ nocase
        $unquoted = /password(\s*(:|=>|=)\s*)(.*)/ nocase

    condition:
        $quoted or $unquoted
}