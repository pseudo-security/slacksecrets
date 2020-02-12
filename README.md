```
 .d8888b.  888                   888       .d8888b.                                    888             
d88P  Y88b 888                   888      d88P  Y88b                                   888             
Y88b.      888                   888      Y88b.                                        888             
 "Y888b.   888  8888b.   .d8888b 888  888  "Y888b.    .d88b.   .d8888b 888d888 .d88b.  888888 .d8888b  
    "Y88b. 888     "88b d88P"    888 .88P     "Y88b. d8P  Y8b d88P"    888P"  d8P  Y8b 888    88K      
      "888 888 .d888888 888      888888K        "888 88888888 888      888    88888888 888    "Y8888b. 
Y88b  d88P 888 888  888 Y88b.    888 "88b Y88b  d88P Y8b.     Y88b.    888    Y8b.     Y88b.       X88 
 "Y8888P"  888 "Y888888  "Y8888P 888  888  "Y8888P"   "Y8888   "Y8888P 888     "Y8888   "Y888  88888P' 

           Created by Pseudo Security [ @pseudo_security ]               
           https://github.com/pseudo-security/slacksecrets
```

`SlackSecrets` is a tool to discover sensitive information in Slack instances (access tokens, API keys, password hashes, etc.). It offers several modes,

1. **Live monitoring** - Leverages the Real-Time Messaging API to scan messages as they're sent.
1. **Historical** - Scans every message since the creation of the Slack workspace. This can be done with the web API _or_ with Slack's "Export Data" feature.

Secrets are matched according to [YARA](https://github.com/virustotal/yara) rules located in the `slacksecrets/rules` directory. YARA is "a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples." It offers increased flexibility over regular expressions, [as well as several other benefits](#why-yara-over-regular-expressions). All YARA rules in the directory will be auto-detected, so additional rules can be easily added. The YARA rules also contain test cases in the `meta` tags to help ensure the rules are correctly matching text.

## Getting Started

`pip install slacksecrets`

```
usage: slacksecrets [-h] [--token TOKEN] [--no-banner] [--skip-db-update]
                    [--exported-dir EXPORTED_DIR]
                    {live,history,exported,reset}

positional arguments:
  {live,history,exported,reset}

optional arguments:
  -h, --help            show this help message and exit
  --token TOKEN
  --no-banner
  --skip-db-update
  --exported-dir EXPORTED_DIR
```

`SlackSecrets` will need a valid Slack API token. `SlackSecrets` will take a token from the command line with the `--token <slack-token>` option, or if a `SLACK_TOKEN` environment variable is set. The `--token` parameter will override the `SLACK_TOKEN` environment variable.

### Live Slack monitoring

`slacksecrets live` (if `SLACK_TOKEN` environment variable is set) or `slacksecrets live --token <slack-token>`.

This will listen to all messages posted to your Slack instance and scan them for any secrets that match according to the rules in the `rules` directory.

### Historical Slack scanning (using web API)

`slacksecrets history` (if `SLACK_TOKEN` environment variable is set) or `slacksecrets history --token <slack-token>`.

This scans every message since the creation of the Slack workspace that match according to the rules in the `rules` directory. Progress will be kept in a sqlite database file named `<workspace-name>.db` so if progress is interrupted, messages will not be scanned multiple times. This will also reduce the likelihood of hitting Slack API's rate limiting.

### Historical Slack scanning (using Slack "Export Data")

1. Ensure you're logged into Slack's web management interface and browse to "Import/Export Data" (https://<workspace-name>.slack.com/services/export)
1. Choose a data range (or entire history) and click "Start Export"
1. When the export is ready, download the .zip file from the "Past Exports" section on the page. The filename is usually `<workspace-name> Slack export <start-date> - <end-date>.zip`.
1. Extract the file to a directory on your local machine.
1. Run `SlackSecrets` with the `exported` command, and specify the extracted directory, like so: `slacksecrets exported --export-dir <path-to-extracted-directory>`.

### Resetting Historical Scanning Progress

`slacksecrets reset`(if `SLACK_TOKEN` environment variable is set) or `slacksecrets reset --token <slack-token>`.

This is most useful if additional rules have been added or need to be tested for Historical Slack scanning (using the web API).

## Testing

Testing uses `pytest`, so running the tests is as simple as running `pytest` from the commandline.

## Contributing

The easiest way to start contributing is to add a YARA rule.

### YARA Rule Template

To ensure consistency and testability, the following template for YARA rules should be used. The meta `author`, `date`, and `description` fields should be added for each rule. If there is a link to a blog post or another resource that provides context to the rule definition, that should be included in the `reference` tag.

Test cases should be in the `test_match_` and `test_no_match_` meta fields. These fields will be automatically tested as part of the build process.

```yaml
rule NameOfRule : TagsGoHere
{
    meta:
        name = ""
        author = ""
        date = "YYYY-MM-DD"
        reference = "https://..." /* if needed */

        /* Test Cases */
        test_match_1 = ""
        test_match_2 = ""
        test_no_match_1 = ""
        test_no_match_2 = ""

    strings:

    condition:
}
```

## Frequently Asked Questions

### Why YARA over regular expressions?

YARA natively [supports regular expressions](https://yara.readthedocs.io/en/latest/writingrules.html#regular-expressions), as well as many other useful features, such as [external variables](https://yara.readthedocs.io/en/latest/writingrules.html#external-variables), [file size](https://yara.readthedocs.io/en/latest/writingrules.html#file-size), and importantly, [metadata tags](https://yara.readthedocs.io/en/latest/writingrules.html#metadata) which are used to define test-cases within the rule file. This aims to solve an issue with existing tools that rely on regular expressions - that is, either no test cases are defined (requiring users to trust the regex is correct), or that test cases are split from the regex definition. Using the metadata tags allows the YARA rules to be included in other tools without the test-cases interfering.

### Why does `SlackSecrets` use a sqlite database?

The Slack API is rate-limited and for large Slack instances, the number of messages posted may be in the tens of millions. The [`conversation.history` API call](https://api.slack.com/methods/conversations.history) is ["Tier 3"](https://api.slack.com/docs/rate-limits#tier_t3) which allows 50 requests per minute. The maximum number of messages returned in a given `conversation.history` request is 1000 (or 50,000 a minute or 3,000,000 an hour). `SlackSecret` uses the local sqlite database to track scanning progress in channels (so as not to repeat scanning the same messages if the scan is interrupted), uploaded files, and of course, discovered secrets.