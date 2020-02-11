rule SquareAccessTokenRule : Square
{
    meta:
        name = "Square Access Token"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "sqOatp-5512345678901SquareToken"

    strings:
        $ = /sqOatp-[0-9A-Za-z-_]{22}/

    condition:
        any of them
}