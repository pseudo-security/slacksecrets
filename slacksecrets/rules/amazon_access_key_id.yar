rule AwsAccessKeyIdRule : AWS
{
    meta:
        name = "AWS Access Key ID"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        /* Test Cases */
        test_match_1 = "AKIA00TESTAWSIDKEY00"

    strings:
        $ = /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/ fullword

    condition:
        any of them
}