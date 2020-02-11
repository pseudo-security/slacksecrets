rule GitLabPatGenericRule : GitLab
{
    meta:
        name = "GitLab Personal Access Token Ageneric-style"
        author = "github.com/pseudo-security"
        date = "2020-01-01"
        test_match_1 = "access-token:ab123mr980pas453201s"

    strings:
        $ = /access.token\s*(:|=>|=)\s*[a-z0-9_]{20}/ fullword ascii

    condition:
        any of them
}