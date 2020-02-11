rule GitLabCiRegTokenRule : GitLab
{
    meta:
        name = "GitLab CI Reg Token"
        author = "github.com/pseudo-security"
        date = "2020-01-01"
        test_match_1 = "token:ab123mr980pas453201s"

    strings:
        $ = /token\s*(:|=>|=)\s*[a-z0-9_]{20}/ fullword ascii

    condition:
        any of them
}