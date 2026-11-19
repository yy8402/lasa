"""Receive a credential document on stdin without terminal echo or value logging."""

import argparse
import json
import os
import sys
import termios
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    destination = args.destination.expanduser()
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    original = None
    if sys.stdin.isatty():
        original = termios.tcgetattr(sys.stdin.fileno())
        settings = list(original)
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, settings)
    print("READY_FOR_CREDENTIALS", flush=True)
    try:
        payload = json.loads(sys.stdin.readline())
        if not isinstance(payload, dict) or not all(
            isinstance(v, str) and v for v in payload.values()
        ):
            raise ValueError("Invalid credential document")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(payload, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        print("Credentials saved with mode 0600.", flush=True)
    finally:
        if original is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, original)


if __name__ == "__main__":
    main()
