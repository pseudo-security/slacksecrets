rule FacebookAccessTokenRule
{
    meta:
        name = "Facebook Access Token"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "EAACEdEose0cBATestAccessCodeForFaceb00k"

    strings:
        $ = /EAACEdEose0cBA[0-9A-Za-z]+/ fullword

    condition:
        any of them
}