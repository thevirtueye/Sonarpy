import os
import signal
import sys
from sonarpy.main import main as _main
from sonarpy.libs.colors import Colors


def _signal_handler(sig, frame):
    print(f"\n{Colors.RED}[!] Scan interrupted by user (Ctrl+C){Colors.RESET}")
    os._exit(0)


def main():
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        _main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
        os._exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
