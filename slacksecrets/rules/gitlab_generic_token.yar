rule GitLabGenericTokenRule : GitLab
{
    meta:
        name = "GitLab Generic Token"
        author = "github.com/pseudo-security"
        date = "2020-01-01"
        test_match_1 = "gitlab-token:ab123mr980pas453201s"

    strings:
        $ = /gitlab.token\s*(:|=>|=)\s*[a-z0-9_]{20}/ fullword ascii

    condition:
        any of them
}