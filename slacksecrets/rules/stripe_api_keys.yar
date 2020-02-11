rule StripeApiRule
{
    meta:
        name = "Stripe API Keys"
        author = "github.com/pseudo-security"
        date = "2020-01-01"
        description = "Stripe API Keys"

        /* Test Cases */
        test_match_1 = "sk_live_123456789012345678901234"
        test_match_2 = "sk_test_123456789012345678901234"
        test_match_4 = "rk_test_123456789012345678901234"
        test_match_3 = "the creds are sk_test_123456789012345678901234, and then for live: sk_live_123456789012345678901234"

    strings:
        $ = /(r|s)k_(live|test)_[0-9a-zA-Z]{24}/

    condition:
        any of them
}