from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from typing import Mapping


from .audit import write_audit


MAX_FAILS = 5
WINDOW_SECONDS = 300.0
LOCK_SECONDS = 300.0
FAILS_DELAY_SECS = 0.25

_DUMMY_SALT = b"0" * 16
_DUMMY_HASH = hashlib.scrypt(b"dummy_password", salt=_DUMMY_SALT, n=16384, r=8, p=1,dklen=64)




def verify_password(input_pw: str, stored_salt_b64: str, stored_hash_b64: str, n: int=16384, r: int=8, p: int=1,dklen: int=32) -> bool:
    try:
        salt = base64.b64decode(stored_salt_b64)
        stored_hash = base64.b64decode(stored_hash_b64)

        computed_hash=hashlib.scrypt(input_pw.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)

        return secrets.compare_digest(computed_hash, stored_hash)
    except Exception:
        return False


class AuthService:
    def __init__(self, users: Mapping[str, Mapping[str, object]]) -> None:
        self.users = users
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def authenticate(self, username: str, password: str) -> bool:
        now = time.monotonic()
        uname = ""
        if isinstance(username, str):
            uname=username

        with self._lock:
            locked_until = self._locked_until.get(uname, 0.0)
            if now < locked_until:
                write_audit(user=uname, op="auth", path="/auth", allowed=False, reason="Account locked due to repeated failures",model="AuthN")
                return False
            if locked_until:
                self._locked_until.pop(uname, None)

        record = self.users.get(uname)

        if record is None:
            hashlib.scrypt( (password if isinstance(password, str) else "").encode("utf-8"), salt=_DUMMY_SALT, n=16384, r=8, p=1, dklen=len(_DUMMY_HASH))
            ok = False
        else:
            pw = ""
            if isinstance(password, str):
                pw = password

            salt_b64 = str(record.get("salt", ""))
            hash_b64 = str(record.get("password hash", ""))
            n = int(record.get("n", 16384))
            r = int(record.get("r", 8))
            p = int(record.get("p", 1))

            dklen = int(record.get("dklen", 64))

            ok = verify_password(pw, salt_b64, hash_b64, n=n, r=r, p=p, dklen=dklen)

            if ok:
                with self._lock:
                    self._failures.pop(uname, None)
                    self._locked_until.pop(uname, None)

                    write_audit(user=uname, op="auth", path="/auth", allowed=True, reason="Authentication succeeded", model="AuthN")

                    return True

                time.sleep(FAILS_DELAY_SECS)
                after_delay = time.monotonic()

                locked_now = False

                with self._lock:
                    recent = []
                    for timestamp in self._failures.get(uname, []):
                        if (after_delay - timestamp) <= WINDOW_SECONDS:
                            recent.append(timestamp)
                    recent.append(after_delay)
                    if len(recent) >= MAX_FAILS:
                        self._failures.pop(uname, None)
                        self._locked_until[uname] = after_delay + LOCK_SECONDS
                        locked_now = True

                    else:
                        self._failures[uname] = recent

                    reason = ("Account locked due to repeated failures" if locked_now else "Invalid username or password")

                    write_audit(user=uname, op="auth", path="/auth", allowed=False, reason=reason, model="AuthN")
                    return False