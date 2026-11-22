from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
from pathlib import Path
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUT = BASE_DIR / "data" / "users.json"

DEFAULT_USERS = ["alice", "bob", "carol", "dave", "eve"]
DEFAULT_N = 16384
DEFAULT_R = 8
DEFAULT_P = 1
DEFAULT_DKLEN = 64


def create_user_record(username: str, password: str, *, n: int = DEFAULT_N, r: int = DEFAULT_R, p:int = DEFAULT_P, dklen:int= DEFAULT_DKLEN) -> dict[str, object]:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)
    return { "username": username, "salt": base64.b64encode(salt).decode("ascii"), "password_hash": base64.b64encode(digest).decode("ascii"), "n": n, "r": r, "p": p, "dklen": dklen}



def main() -> None:
    parser = argparse.ArgumentParser(description="Generate data/users.json with salted scrypt password hashes.")

    parser.add_argument("username", nargs="*", default=DEFAULT_USERS, help="Username to create or update")

    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output for users.json")

    args = parser.parse_args()

    out_path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)

    users_by_name = {}

    if out_path.exists():
        existing = json.loads(out_path.read_text(encoding="utf-8"))
        if isinstance(existing, list):
            for entry in existing:
                users_by_name[entry["username"]] = entry
        elif isinstance(existing, dict):
            for uname, entry in existing.items():
                record = dict(entry)
                record.setdefault("username", uname)
                users_by_name[uname] = record

    for username in args.username:
        pw1 = getpass.getpass(f"Password for '{username}': ")
        pw2 = getpass.getpass(f"Confirm password for '{username}': ")
        if not pw1 or pw1 != pw2:
            raise SystemExit(f"Error: passwords for username are empty or don't match")
        users_by_name[username] = create_user_record(username, pw1)

    output = list(users_by_name.values())
    out_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(output)} user records to {out_path}")

if __name__ == "__main__":
    main() 