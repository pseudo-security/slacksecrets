rule UriUserPasswordRule
{
    meta:
        name = "URI User Password"
        author = "github.com/pseudo-security"
        date = "2020-01-01"
        test_match_1 = "https://username:password@localhost.local/"
        test_no_match_1 = "https://username-password-localhost.local/"

    strings:
        $ = /([\w+]{1,24})(:\/\/)([^$<]{1})([^\s\";]{1,}):([^$<]{1})([^\s\";]{1,})@[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,24}([^\s]+)/ fullword

    condition:
        any of them
}