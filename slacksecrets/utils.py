import math
import string
from enum import Enum
from colorama import Fore

HEX_ALPHABET = string.hexdigits
BASE64_ALPHABET = string.ascii_letters + string.digits + "+/="


def banner():
    print("""
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
""")


class LOGLEVEL(Enum):
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    SUCCESS = 3


def log(level: LOGLEVEL, message: str):
    if level == LOGLEVEL.WARNING:
        prefix = Fore.YELLOW + "[~]"
    elif level == LOGLEVEL.ERROR:
        prefix = Fore.RED + "[x]"
    elif level == LOGLEVEL.SUCCESS:
        prefix = Fore.GREEN + "[+]"
    else:
        prefix = "[ ]"
    print(prefix + Fore.RESET + " " + message)


def info(message: str):
    log(LOGLEVEL.INFO, message)


def warning(message: str):
    log(LOGLEVEL.WARNING, message)


def error(message: str):
    log(LOGLEVEL.ERROR, message)


def success(message: str):
    log(LOGLEVEL.SUCCESS, message)


def mask_slack_token(token):
    """
    Preserve the token prefix (xoxp is personal token, xoxb is a bot, etc.).
    Mask all other characters except for the final 8 chars in the Slack token.
    This will help people debug their token permissions without logging full Slack
    tokens to the console / logs.
    """
    toks = token.split('-')
    return "{}-{}-{}".format(
        toks[0],
        '-'.join('*' * len(tok) for tok in toks[1:len(toks) - 1]),
        ('*' * (len(toks[len(toks) - 1]) - 8)) + toks[len(toks) - 1][-8:])


def dump_config(args: dict):
    info("Dumping running configuration:")
    max_keylen = max(map(len, args.keys()))
    for key in sorted(args.keys()):
        val = args[key]
        if key == "token":
            val = mask_slack_token(val)
        info("\t" + key.ljust(max_keylen) + "\t" + str(val))


def calc_entropy_shannon(str="", alphabet=None):
    # http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    if alphabet is None:
        alphabet = []
    entropy = 0
    for c in alphabet:
        p_c = float(str.count(c)) / len(str)
        if p_c > 0:
            entropy += (-p_c * math.log(p_c, 2))
    return entropy
