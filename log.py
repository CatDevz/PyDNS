from datetime import datetime
import os

__LOG_DEBUG = os.environ.get("LOG_DEBUG", "").upper() == "TRUE"


class colors:
    RESET = "\033[0m"
    GREY = "\033[90m"
    BLUE = "\033[34m"
    GREEN = "\33[32m"
    YELLOW = "\033[33m"
    RED = "\033[91m"
    BG_RED = "\033[41m"

INFO = f"{colors.BLUE}INFO{colors.RESET}"
WARN = f"{colors.YELLOW}WARN{colors.RESET}"
ERROR = f"{colors.RED}ERROR{colors.RESET}"
CRITICAL = f"{colors.BG_RED} CRITICAL {colors.RESET}"
DEBUG = f"{colors.GREY}DEBUG{colors.RESET}"

def log(msg, prefix = INFO):
    if not prefix == DEBUG or __LOG_DEBUG:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("[{}] {}: {}".format(timestamp, prefix, msg))
