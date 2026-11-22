#!/usr/bin/env python3
"""CTF: plant the flag and the demo directory layout inside a jail.

    python3 ctf/setup_flag.py                 # uses server/sftp_root
    python3 ctf/setup_flag.py --jail /tmp/j   # any other jail (used by run_attacks.py)

On POSIX the flag file gets mode 0600 (owner only). The policy entries that
protect it inside the SFTP server are in ctf/flag_config.py.
"""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from flag_config import FLAG, FLAG_PATH, REQUIRED_POLICY  # noqa: E402

DEFAULT_JAIL = Path(__file__).resolve().parents[1] / "server" / "sftp_root"


def plant(jail: Path) -> Path:
    jail = Path(jail)
    for rel in ("public", "projects", "admin/ctf"):
        (jail / rel).mkdir(parents=True, exist_ok=True)
    (jail / "public" / "welcome.txt").write_text("Public area. Nothing to see here.\n")
    (jail / "projects" / "plan.txt").write_text("Internal project notes (decoy).\n")
    flag_file = jail / FLAG_PATH.lstrip("/")
    flag_file.write_text(FLAG + "\n")
    if os.name != "nt":
        os.chmod(jail / "admin", 0o750)
        os.chmod(jail / "admin" / "ctf", 0o750)
        os.chmod(flag_file, 0o600)
    return flag_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jail", default=str(DEFAULT_JAIL))
    args = parser.parse_args()
    flag_file = plant(Path(args.jail))
    print(f"Flag planted at {flag_file}")
    print("Policy entries in data/ that protect it (see ctf/flag_config.py):")
    for name, entries in REQUIRED_POLICY.items():
        print(f"  {name}: {entries}")


if __name__ == "__main__":
    main()
