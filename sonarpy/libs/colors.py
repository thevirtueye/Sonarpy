import os
import sys


class Colors:
    ENABLED = (
        sys.stdout.isatty()
        and (
            os.name != "nt"
            or os.environ.get("WT_SESSION")
            or os.environ.get("TERM") == "xterm"
            or os.environ.get("ANSICON")
        )
    )

    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            ENABLED = True
        except Exception:
            pass

    RED = "\033[91m" if ENABLED else ""
    GREEN = "\033[92m" if ENABLED else ""
    YELLOW = "\033[93m" if ENABLED else ""
    BLUE = "\033[94m" if ENABLED else ""
    MAGENTA = "\033[95m" if ENABLED else ""
    CYAN = "\033[96m" if ENABLED else ""
    WHITE = "\033[97m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""
    DIM = "\033[2m" if ENABLED else ""
    UNDERLINE = "\033[4m" if ENABLED else ""
    RESET = "\033[0m" if ENABLED else ""

    @classmethod
    def disable(cls):
        for attr in [
            "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA",
            "CYAN", "WHITE", "BOLD", "DIM", "UNDERLINE", "RESET",
        ]:
            setattr(cls, attr, "")

    @classmethod
    def enable(cls):
        codes = {
            "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
            "BLUE": "\033[94m", "MAGENTA": "\033[95m", "CYAN": "\033[96m",
            "WHITE": "\033[97m", "BOLD": "\033[1m", "DIM": "\033[2m",
            "UNDERLINE": "\033[4m", "RESET": "\033[0m",
        }
        for attr, code in codes.items():
            setattr(cls, attr, code)
