#!/usr/bin/env python3
"""Interactive PTY smoke test for SimpleCrypt.

Drives the real terminal binary inside tmux: creates a disposable vault,
adds a record, verifies persistence across a lock/unlock cycle, rejects a
wrong password, and confirms no plaintext leaks into the vault file.

Usage: python3 scripts/smoke.py <path-to-simplecrypt-binary>
"""

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SESSION = "simplecrypt-smoke"
MASTER = "synthetic smoke test master password"
WRONG = "totally the wrong password"
LABEL = "Smoke Test Login"
SECRET_MARKER = "smoke-test-secret-sentinel"


def tmux(*args: str) -> str:
    result = subprocess.run(["tmux", *args], capture_output=True, text=True, check=True)
    return result.stdout


def capture() -> str:
    return tmux("capture-pane", "-t", SESSION, "-p")


def send(*keys: str) -> None:
    tmux("send-keys", "-t", SESSION, *keys)


def send_literal(text: str) -> None:
    tmux("send-keys", "-t", SESSION, "-l", text)


def wait_for(needle: str, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        last = capture()
        if needle in last:
            return last
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {needle!r}. Last screen:\n{last}")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        print(f"Binary not found: {binary}", file=sys.stderr)
        return 2
    if shutil.which("tmux") is None:
        print("tmux is required for this smoke test.", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="simplecrypt-smoke-") as tmp:
        vault = Path(tmp) / "vault.scv"
        subprocess.run(["tmux", "kill-session", "-t", SESSION], capture_output=True)
        tmux(
            "new-session", "-d", "-s", SESSION, "-x", "100", "-y", "32",
            f"{binary} --vault {vault} --idle-timeout 86400",
        )
        try:
            wait_for("Create a master password")

            # Create the vault.
            send_literal(MASTER)
            send("Enter")
            send_literal(MASTER)
            send("Enter")
            wait_for("Vault created")

            # Add a Login record.
            send("a")
            wait_for("Login")
            send("Enter")
            wait_for("New record")
            send("C-u")
            send_literal(LABEL)
            # Focus order: Label, FieldList, Name, Kind, Secret, Value, ...
            for _ in range(5):
                send("Tab")  # Label -> ... -> Value (Username field)
            send_literal("octocat")
            for _ in range(4):
                send("BTab")  # Value -> Secret -> Kind -> Name -> FieldList
            send("j")  # select Password field
            for _ in range(5):
                send("Tab")  # FieldList -> ... -> Generate
            send("Enter")  # generate a password
            wait_for("Generated a")
            send("C-s")
            wait_for("Record saved")

            screen = capture()
            assert LABEL in screen, f"Saved label missing from browse view:\n{screen}"

            # Lock and reject a wrong password.
            send("L")
            wait_for("locked")
            send_literal(WRONG)
            send("Enter")
            wait_for("Wrong password")

            # Unlock with the correct password and confirm persistence.
            send_literal(MASTER)
            send("Enter")
            wait_for(LABEL)

            assert vault.exists(), "Vault file was not created."
            mode = oct(vault.stat().st_mode)[-3:]
            assert mode == "600", f"Vault file mode is {mode}, expected 600."
            raw = vault.read_bytes()
            for leak in (LABEL.encode(), b"octocat", MASTER.encode()):
                assert leak not in raw, f"Plaintext leaked into vault file: {leak!r}"

            # Quit.
            send("q")
            time.sleep(0.5)

            print("OK: create, save, lock, wrong-password rejection, persistence, "
                  "and ciphertext-only storage all verified.")
            return 0
        finally:
            subprocess.run(["tmux", "kill-session", "-t", SESSION], capture_output=True)


if __name__ == "__main__":
    raise SystemExit(main())
