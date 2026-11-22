from __future__ import annotations

import base64
import binascii
import csv
from functools import lru_cache
import json
import logging
from pathlib import Path
import posixpath
from types import MappingProxyType
from typing import Mapping

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MAX_FILE_SIZE = 1 << 20
RBAC_ACTIONS = ("stat", "list", "read", "write", "mkdir")

VALID_MAC_LEVELS = frozenset({"public", "internal", "confidential"})

logger = logging.getLogger(__name__)

class DataError(RuntimeError):
    """Missing, broken or inconsisted data file"""

def _read_json(path: Path) -> object:
    if not path.exists():
        raise DataError(f"Missing required policy file: {path}")
    try:
        _check_size(path)
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DataError(f"Malformed JSON in {path.name}: {exc}")

def _check_size(path: Path) -> None:
    if not path.exists():
        raise DataError(f"Missing required: {path.name}")
    if path.stat().st_size > MAX_FILE_SIZE:
        raise DataError(f"Problems with {path.name}: larger than {MAX_FILE_SIZE} bytes")

def _no_duplicates_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DataError(f"Duplicate key {key!r}")

        result[key] = value
    return result




def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        raise DataError(f"Missing required file: {path}")
    try:
        _check_size(path)
        with path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                raise DataError(f"Problems with CSV header in {path.name}: empty header")
            
            
            headers = []
            for col in reader.fieldnames:
                if col and col.strip():
                    headers.append(col)

            rows = []

            for row in reader:
                if None in row or any(val is None for val in row.values()):
                    raise ValueError(f"Problems with CSV row in {path.name}: {row}")
                cleaned = { 
                    k.strip(): v.strip()
                    for k,v in row.items()
                    if k is not None and k.strip()
                }


                if any(cleaned.values()):
                    rows.append(cleaned)

            return headers, rows
    except (OSError, UnicodeDecodeError, ValueError, csv.Error) as exc:
        raise DataError(f"Problems with CSV in {path.name}: {exc}") from exc


def load_users(data_dir: Path = DATA_DIR) -> Mapping[str, Mapping[str, object]]:
    path = data_dir / "users.json"
    raw = _read_json(path)
    if not isinstance(raw, list) or not raw:
        raise DataError("Problems with users.json: expected a JSON array")


    required_fields={"username", "salt", "password_hash", "n", "r", "p", "dklen"}
    users = {}
    for item in raw:
        if not isinstance(item, dict) or not required_fields.issubset(item.keys()):
            raise DataError(f"Problems with user entry in users.json: {item}")
        username=item["username"]
        if not isinstance(username, str) or not username.strip():
            raise DataError(f"Problems with user entry in users.json: {item}")

        if username in users:
            raise DataError(f"Duplicated user: {username}")
        try:
            salt = base64.b64decode(item["salt"], validate=True)
            digest = base64.b64decode(item["password_hash"], validate=True)
            n, r, p, dklen = (item[key] for key in ("n", "r", "p", "dklen"))
            if (any(type(v) is not int for v in (n, r, p, dklen))
                    or n < 2 or n > 32768 or n & (n - 1)
                    or not 1 <= r <= 8 or not 1 <= p <= 4
                    or not 16 <= dklen <= 64 or len(salt) < 16 or len(digest) != dklen):
                raise ValueError("invalid scrypt parameters or hash lengths")
        except (ValueError, TypeError, binascii.Error):
            raise DataError(f"Invalid password record for {username!r}") from None
        users[username] = MappingProxyType(dict(item))


    logger.info(f"Loaded {path.name}({len(users)}) ")
    return MappingProxyType(users)


def load_user_roles(known_users: Mapping[str, object], data_dir: Path = DATA_DIR) -> Mapping[str, tuple[str, ...]]:
    path = data_dir / "user_roles.json"
    raw = _read_json(path)

    if not isinstance(raw, dict) or not raw:
        raise DataError("Problems with user_roles.json: expected a JSON object")

    user_roles = {}

    for username, roles in raw.items():
        if username not in known_users:
            raise DataError(f"Problems with user_roles.json: uknown user {username!r}")


        if not isinstance(roles, list) or not roles or not all(isinstance(role, str) and role.strip() for role in roles):
            raise DataError(f"Problems with user_roles.json: user {username!r} needs a non-empty list of roles")

        if len(set(roles)) != len(roles):
            raise DataError(f"Problems with user_roles.json: duplicate role for {username!r}")

        user_roles[username] = tuple(roles)

    missing = sorted(set(known_users) - set(user_roles))

    if missing:
        raise DataError(f"Problems with user_roles.json: no roles for {', '.join(missing)}")

    logger.info("loaded %s (%d entries)", path.name, len(user_roles))
    return MappingProxyType(user_roles)


def load_groups(known_users: Mapping[str, object], data_dir: Path = DATA_DIR) -> Mapping[str, tuple[str, ...]]:
    path = data_dir / "groups.json"
    raw = _read_json(path)
    if not isinstance(raw, dict) or not raw:
        raise DataError("Problems with groups.json: expected a non-empty JSON object")

    groups = {}

    for group, members in raw.items():
        if not group.strip():
            raise DataError("Problems with groups.json: empty group name")

        if not isinstance(members, list) or not members:
            raise DataError("Problems with groups.json: group {group!r}. Needs a non-empty list of users")

        for member in members:
            if member not in known_users:
                raise DataError(f"Problems with groups.json: group {group!r}: uknown user{member!r}")

        if len(set(members)) != len(members):
            raise DataError(f"Problems with groups.json: duplicate member in {group!r}")

        groups[group] = tuple(members)


    logger.info("loaded %s (%d entries)", path.name, len(groups))
    return MappingProxyType(groups)



def load_mac_labels(known_users: Mapping[str, object], data_dir: Path = DATA_DIR) -> Mapping[str, object]:
    path = data_dir / "mac_labels.json"
    raw = _read_json(path)
    if not isinstance(raw, dict) or set(raw) != {"levels", "paths", "users"}:
        raise DataError("Problems with max_labels.json: keys must be exactly levels, paths and users")


    levels = raw["levels"]
    if (not isinstance(levels, list) or len(set(levels)) != len(levels) or levels != ["public", "internal", "confidential"]):
        raise DataError(f"Problems with mac_labels.json: levels must list public, internal, confidential once each, lowest first")

    paths = raw["paths"]

    if (not isinstance(paths, dict) or "/" not in paths):
        raise DataError(f"Problems with mac_labels.json: invalid path {path!r}")
    for prefix, level in paths.items():
        if level not in VALID_MAC_LEVELS:
            raise DataError(f"Problems with mac_labels.json: path {prefix} has uknown levels {level!r}")
        if(not prefix.startswith("/") or posixpath.normpath(prefix) != prefix or (prefix.startswith("//") or "\\" in prefix or "\x00" in prefix)):
            raise DataError(f"Problems with mac_labels.json: invalid path {prefix!r}")
        if level not in VALID_MAC_LEVELS:
            raise DataError(f"Problem with mac_labels.json: path {prefix} has uknown level {level!r}")

    users = raw["users"]

    if not isinstance(users, dict):
        raise DataError(f"Problems with mac_labels.json: users must be an object user -> level")
    for user, level in users.items():
        if user not in known_users:
            raise DataError(f"Problems with mac_labels.json: uknown user {user!r}")
        if level not in VALID_MAC_LEVELS:
            raise DataError(f"Problems with mac_labels.json: user {user!r} has unknown clearance {level!r}")     

    missing = sorted(set(known_users) - set(users))
    if missing:
        raise DataError(f"Problems with mac_lebels.json: no clearance for {', '.join(missing)}")

    logger.info("loaded %s (%d entries)", path.name, len(paths))

    return MappingProxyType({"levels": tuple(levels), "paths": MappingProxyType(dict(paths)), "users": MappingProxyType(dict(users))})



def load_role_permissions(user_roles: Mapping[str, tuple[str, ...]], data_dir: Path=DATA_DIR) -> tuple[Mapping[str, str], ...]:
    path = data_dir / "role_perms.csv"

    headers, rows = _read_csv(path)

    actions = headers[2:]

    if headers[:2] != ["role", "prefix"] or not actions or not set(actions) <=set(RBAC_ACTIONS):
        raise DataError(f"Problems with csv header in role_perms.csv: must be role, prefix followed by columns from {', '.join(RBAC_ACTIONS)}")

    known_roles = set()

    for roles in user_roles.values():
        for role in roles:
            known_roles.add(role)

    rules = []
    seen = set()

    for line, row in enumerate(rows, 2):
        subject = row["role"]
        prefix = row['prefix']

        if subject.startswith("user:"):
            if subject[5:] not in user_roles:
                raise DataError(f"Problems with role_perms.csv row {line}: unknown user {subject!r}")

        elif subject not in known_roles:
            raise DataError(f"Problems with roles_perms.csv row {line}: role {subject!r} is not assigned to anyone")
        if (not prefix.startswith("/") or posixpath.normpath(prefix) != prefix or (prefix.startswith("//") or "\\" in prefix or "\x00" in prefix)):
                raise DataError(f"Problems with role_perms.csv: invalid path {prefix!r}")

        cells = [row[action] for action in actions]

        for cell in cells:
            if cell not in ("", "x", "allow", "deny"):
                raise DataError(f"Problems with role_perms.csv row {line}: {cell!r} must be allow, deny or empty")
        if not any(cells):
            raise DataError(f"Problems with role_perms.csv row {line}: rule does nothing")
        if (subject, prefix) in seen:
            raise DataError(f"Probems with role_perms.csv row {line}: duplicate rule for {subject} on {prefix}")
        seen.add((subject, prefix))
        rules.append(MappingProxyType(row))


    if not rules:
        raise DataError("Problems with role_perms.csv: no rules")
    logger.info("loaded %s (%d entries)", path.name, len(rules))
    return tuple(rules)


def load_dac_owners(known_users: Mapping[str, object], groups: Mapping[str, tuple[str, ...]], data_dir: Path=DATA_DIR) -> tuple[Mapping[str, object], ...]:
    path_dir = data_dir / "dac_owners.csv"
    headers, rows = _read_csv(path_dir)
    if headers != ["prefix", "owner", "group", "mode"]:
        raise DataError("Problems with csv header in dac_owners: must be prefix,owner, group and mode")

    owners = []
    seen = set()

    for line, row in enumerate(rows, 2):
        prefix = row["prefix"]
        if (not prefix.startswith("/") or posixpath.normpath(prefix) != prefix or (prefix.startswith("//") or "\\" in prefix or "\x00" in prefix)):
                        raise DataError(f"Problems with dac_owners.csv: invalid path {prefix!r}")
        if prefix in seen:
            raise DataError(f"Problems with dac_owners.csv row {line}: duplicate prefix")

        seen.add(prefix)

        if not row["owner"] or not row["group"]:
            raise DataError(f"Problems with dac_owners.csv row {line}: owners and groups must not be empty")
        if row["owner"] not in known_users:
            raise DataError(f"dac_owners.csv row {line}: unknown owner")
        if row["group"] not in groups:
            raise DataError(f"dac_owners.csv row {line}: unknown group")
        mode = row["mode"]
        if len(mode) not in (3,4) or any(c not in "01234567" for c in mode):
            raise DataError(f"Problems with dac_owners.csv row {line}: must be octal(e.g: 0750)")

        owners.append(MappingProxyType({"prefix": prefix, "owner": row["owner"], "group": row["group"], "mode": int(mode, 8)}))

    if "/" not in seen:
        raise DataError("Problems with dac_owners.csv: the root '/' needs an owner row")

    logger.info("loaded %s (%d entries)", path_dir.name, len(owners))
    return tuple(owners)





def _load_all(data_dir: Path = DATA_DIR) -> Mapping[str, object]:
    data_dir = Path(data_dir)
    users = load_users(data_dir)
    user_roles = load_user_roles(users, data_dir)
    groups = load_groups(users, data_dir)
    return MappingProxyType({
        "users": users,
        "user_roles": user_roles,
        "groups": groups,
        "mac": load_mac_labels(users, data_dir),
        "role_perms": load_role_permissions(user_roles, data_dir),
        "dac_owners": load_dac_owners(users, groups, data_dir),
    })


def load_all(data_dir: Path = DATA_DIR) -> Mapping[str, object]:
    try:
        return _load_all(data_dir)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise DataError(f"Malformed static data: {type(exc).__name__}") from None


# Compatibility with the original WP2 spelling.
laod_all = load_all


@lru_cache(maxsize=1)
def get_data() -> Mapping[str, object]:
    return load_all()
