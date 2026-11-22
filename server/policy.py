import csv
import json
import logging
import posixpath
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("policy")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
AUDIT_PATH = Path(__file__).resolve().parent / "audit.jsonl"
DATA_FILES = ["user_roles.json", "role_perms.csv", "mac_labels.json", "dac_owners.csv", "groups.json"]

READ_OPS = {"realpath", "stat", "list", "read"}
WRITE_OPS = {"write", "mkdir"}
R, W, X = 4, 2, 1


class PolicyConfigError(RuntimeError):
    """A data file is missing or malformed. server.py turns RuntimeError into a clean exit(1)."""

class Policy:
    def __init__(self, data_dir=DATA_DIR, audit_path=AUDIT_PATH):
        self.audit_path = Path(audit_path)

        data = {}
        for name in DATA_FILES:
            path = Path(data_dir) / name
            try:
                with open(path, encoding="utf-8", newline="") as f:
                    data[name] = list(csv.DictReader(f)) if name.endswith(".csv") else json.load(f)
            except (OSError, ValueError, csv.Error) as e:
                raise PolicyConfigError(f"cannot load {path}: {e}") from None
            log.info("loaded %s", path)

        try:
            self.roles = {user: set(roles) for user, roles in data["user_roles.json"].items()}
            self.rules = [(row["role"], row["prefix"], row) for row in data["role_perms.csv"]]
            mac = data["mac_labels.json"]
            self.levels = {name: i for i, name in enumerate(mac["levels"])}
            self.labels, self.clearance = mac["paths"], mac["users"]
            self.owners = {row["prefix"]: (row["owner"], row["group"], int(row["mode"], 8))
                           for row in data["dac_owners.csv"]}
            self.groups = {group: set(members) for group, members in data["groups.json"].items()}

            if "/" not in self.labels or "/" not in self.owners:
                raise ValueError('mac_labels.json and dac_owners.csv need an entry for "/"')
            for label in [*self.labels.values(), *self.clearance.values()]:
                if label not in self.levels:
                    raise ValueError(f"unknown label {label!r}")
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            raise PolicyConfigError(f"malformed data in {data_dir}: {e!r}") from None

    def authorize(self, user, op, path):
        if op not in READ_OPS | WRITE_OPS:
            allowed, reason = False, f"unknown operation {op!r}"
        elif user not in self.roles:
            allowed, reason = False, "unknown user"
        elif not (isinstance(path, str) and path.startswith("/") and not path.startswith("//")
                  and "\\" not in path and "\x00" not in path and posixpath.normpath(path) == path):
            allowed, reason = False, "non-canonical path (possible traversal)"
        else:
            allowed, reason = True, "allowed by DAC, MAC and RBAC"
            for ok, why in (self.check_dac(user, op, path),
                            self.check_mac(user, op, path),
                            self.check_rbac(user, op, path)):
                if not ok:
                    allowed, reason = False, why
                    break

        record = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "user": user, "op": op, "path": path, "allowed": allowed, "reason": reason}
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=repr) + "\n")
        return allowed, reason

    def check_dac(self, user, op, path):
        target, need = {
            "realpath": (path, 0),
            "stat": (path, 0),
            "list": (path, R | X),
            "read": (path, R),
            "write": (path, W),
            "mkdir": (posixpath.dirname(path), W),
        }[op]

        checks = []
        parent = path
        while parent != "/":
            parent = posixpath.dirname(parent)
            checks.append((parent, X))
        checks.append((target, need))

        for checked, wanted in checks:
            entry = checked
            while entry not in self.owners:
                entry = posixpath.dirname(entry)
            owner, group, mode = self.owners[entry]
            if user == owner:
                bits = (mode >> 6) & 7
            elif user in self.groups.get(group, ()):
                bits = (mode >> 3) & 7
            else:
                bits = mode & 7
            if (bits & wanted) != wanted:
                return False, f"DAC: {op} denied at {checked}"
        return True, "DAC ok"

    def inherit(self, user, path, kind):
        if kind not in ("file", "dir") or not path.startswith("/") or path == "/":
            raise ValueError(f"cannot register {kind!r} {path!r}")
        entry = posixpath.dirname(path)
        while entry not in self.owners:
            entry = posixpath.dirname(entry)
        owner, group, mode = self.owners[entry]
        if kind == "file":
            mode &= 0o666
        self.owners.setdefault(path, (user, group, mode))


    def check_mac(self, user, op, path):
        if user not in self.clearance:
            return False, "MAC: user has no clearance"
        entry = path
        while entry not in self.labels:
            entry = posixpath.dirname(entry)
        label = self.levels[self.labels[entry]]
        clearance = self.levels[self.clearance[user]]
        if op in READ_OPS and label > clearance:
            return False, "MAC: no read up"
        if op in WRITE_OPS and label < clearance:
            return False, "MAC: no write down"
        return True, "MAC ok"

    def check_rbac(self, user, op, path):
        action = "stat" if op == "realpath" else op
        subjects = self.roles[user] | {f"user:{user}"}
        granted = False
        for subject, prefix, row in self.rules:
            if subject in subjects and (prefix == "/" or path == prefix or path.startswith(prefix + "/")):
                cell = (row.get(action) or "").strip()
                if cell == "deny":
                    return False, f"RBAC: {action} denied for {subject} on {prefix}"
                granted = granted or bool(cell)
        if granted:
            return True, "RBAC ok"
        return False, f"RBAC: no role grants {action}"


current = None


def init(data_dir=DATA_DIR, audit_path=AUDIT_PATH):
    global current
    try:
        current = Policy(data_dir, audit_path)
    except PolicyConfigError as e:
        log.error("%s", e)
        raise
    return current


def authorize(user, op, path):
    if current is None:
        raise RuntimeError("policy.init() was not called")
    return current.authorize(user, op, path)


def inherit(user, path, kind):
    if current is None:
        raise RuntimeError("policy.init() was not called")
    return current.inherit(user, path, kind)
