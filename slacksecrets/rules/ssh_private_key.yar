rule SshPrivateKeyRule
{
    meta:
        name = "SSH Private Key"
        author = "github.com/pseudo-security"
        date = "2020-01-01"

        test_match_1 = "-----BEGIN OPENSSH PRIVATE KEY-----"
        test_match_1_externals = "{'filename': 'super_secret.pem'}"
    strings:
        $ = /-{5}BEGIN (EC|RSA|DSA|OPENSSH) PRIVATE KEY-{5}/

    condition:
        filename matches /(.*).pem/ and any of them
}