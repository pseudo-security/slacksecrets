rule SocialSecurityNumberRule
{
    meta:
        name = "Social Security Number"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "Don't share 123-45-6789 with anyone"

    strings:
        $ = /[0-9]{3}-[0-9]{2}-[0-9]{4}/ fullword

    condition:
        any of them
}