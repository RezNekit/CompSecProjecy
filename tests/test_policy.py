import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
from policy import Policy

BASE = {
    "user_roles.json": {"alice": ["admin"], "bob": ["analyst"], "eve": ["guest"]},
    "groups.json": {"admins": ["alice"], "analysts": ["bob"], "staff": ["alice", "bob", "eve"]},
    "mac_labels.json": {
        "levels": ["public", "internal", "confidential"],
        "paths": {"/": "public", "/projects": "internal", "/admin": "confidential"},
        "users": {"alice": "confidential", "bob": "internal", "eve": "public"},
    },
    "role_perms.csv": "role,prefix,read,write,list,stat,mkdir\n"
                      "guest,/public,x,,x,x,\n"
                      "analyst,/projects,x,x,x,x,x\n"
                      "admin,/,x,x,x,x,x\n"
                      "user:eve,/public/archive,deny,,,,\n",
    "dac_owners.csv": "prefix,owner,group,mode\n"
                      "/,alice,staff,0755\n"
                      "/projects,alice,analysts,0770\n"
                      "/admin,alice,admins,0700\n",
}


def make_policy(tmp_path, changes=None):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    for name, content in {**BASE, **(changes or {})}.items():
        (data / name).write_text(content if isinstance(content, str) else json.dumps(content))
    return Policy(data, tmp_path / "audit.jsonl")


def dac(*extra_rows):
    return BASE["dac_owners.csv"] + "".join(row + "\n" for row in extra_rows)



def test_dac_owner_group_other(tmp_path):
    """Owner/group/other mode bits grant only their corresponding rights."""
    p = make_policy(tmp_path, {"dac_owners.csv": dac("/notes.txt,alice,analysts,0640")})
    assert p.check_dac("alice", "read", "/notes.txt")[0]
    assert p.check_dac("alice", "write", "/notes.txt")[0]
    assert p.check_dac("bob", "read", "/notes.txt")[0]
    assert not p.check_dac("bob", "write", "/notes.txt")[0]
    assert not p.check_dac("eve", "write", "/notes.txt")[0]


def test_dac_directory_execute_bit_controls_ls_and_stat(tmp_path):
    """Directory execute permission controls traversal and listing."""
    p = make_policy(tmp_path, {"dac_owners.csv": dac("/d,alice,staff,0744")})
    assert not p.check_dac("bob", "list", "/d")[0]
    assert not p.check_dac("bob", "stat", "/d/f")[0]
    p = make_policy(tmp_path, {"dac_owners.csv": dac("/d,alice,staff,0711")})
    assert p.check_dac("bob", "stat", "/d/f")[0]
    assert not p.check_dac("bob", "list", "/d")[0]


def test_dac_inheritance_for_new_files_and_dirs(tmp_path):
    """Creation inherits group and mode without replacing an existing owner."""

    p = make_policy(tmp_path)
    p.inherit("bob", "/projects/plan.txt", "file")
    p.inherit("bob", "/projects/sub", "dir")
    p.inherit("eve", "/projects/plan.txt", "file")
    assert p.owners["/projects/plan.txt"] == ("bob", "analysts", 0o660)
    assert p.owners["/projects/sub"] == ("bob", "analysts", 0o770)


def test_mac_internal_reads_public_and_internal_not_confidential(tmp_path):
    """Internal clearance reads public/internal but never confidential."""
    p = make_policy(tmp_path)
    assert p.check_mac("bob", "read", "/public/a.txt")[0]
    assert p.check_mac("bob", "read", "/projects/a.txt")[0]
    assert p.check_mac("bob", "read", "/admin/a.txt") == (False, "MAC: no read up")


def test_mac_confidential_cannot_write_down(tmp_path):
    """Confidential clearance cannot write to lower-labelled paths."""
    p = make_policy(tmp_path)
    assert p.check_mac("alice", "write", "/public/a.txt") == (False, "MAC: no write down")
    assert p.check_mac("alice", "mkdir", "/projects/d") == (False, "MAC: no write down")
    assert p.check_mac("alice", "write", "/admin/a.txt")[0]


def test_rbac_analyst_projects_but_not_admin_until_admin_role_added(tmp_path):
    """Role union grants admin operations and prefixes respect boundaries."""
    p = make_policy(tmp_path)
    assert p.check_rbac("bob", "read", "/projects/a.txt")[0]
    assert p.check_rbac("bob", "write", "/projects/a.txt")[0]
    assert not p.check_rbac("bob", "write", "/projects2/a.txt")[0]
    assert not p.check_rbac("bob", "mkdir", "/admin/new")[0]
    p = make_policy(tmp_path, {"user_roles.json": {**BASE["user_roles.json"], "bob": ["analyst", "admin"]}})
    assert p.check_rbac("bob", "mkdir", "/admin/new")[0]


def test_rbac_per_user_deny_overrides_roles(tmp_path):
    """Per-user denial overrides every matching role grant."""
    p = make_policy(tmp_path, {"user_roles.json": {**BASE["user_roles.json"], "eve": ["guest", "admin"]}})
    assert p.check_rbac("eve", "read", "/public/a.txt")[0]
    assert not p.check_rbac("eve", "read", "/public/archive/old.txt")[0]

def test_composite_any_model_can_deny(tmp_path):
    """A denial by either DAC or MAC defeats the combined grant."""
    p = make_policy(tmp_path, {"dac_owners.csv": dac("/public/secret.txt,alice,admins,0600")})
    assert p.check_dac("alice", "write", "/projects/plan.txt")[0]
    assert p.authorize("alice", "write", "/projects/plan.txt") == (False, "MAC: no write down")
    assert p.check_mac("eve", "read", "/public/secret.txt")[0]
    assert p.authorize("eve", "read", "/public/secret.txt") == (False, "DAC: read denied at /public/secret.txt")
    assert p.authorize("bob", "write", "/projects/plan.txt")[0]


def test_default_deny_traversal_unknown_user_and_op(tmp_path):
    """Unknown subjects, operations and noncanonical paths fail closed."""
    p = make_policy(tmp_path)
    for path in ["/projects/../admin/flag.txt", "/../etc/passwd", "projects/a",
                 "//admin", "/projects/..\\..\\admin", "/projects/a\x00b"]:
        assert p.authorize("alice", "read", path) == (False, "non-canonical path (possible traversal)")
    assert not p.authorize("mallory", "read", "/public/a.txt")[0]
    assert not p.authorize("bob", "chmod", "/projects/a.txt")[0]

def test_audit_records_allow_and_deny(tmp_path):
    """Allowed and denied decisions each produce a complete audit record."""
    p = make_policy(tmp_path)
    p.authorize("bob", "write", "/projects/plan.txt")
    p.authorize("eve", "read", "/admin/flag.txt")
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    first, second = (json.loads(line) for line in lines)
    assert set(first) == {"timestamp", "user", "op", "path", "allowed", "reason"}
    assert (first["user"], first["op"], first["allowed"]) == ("bob", "write", True)
    assert (second["user"], second["path"], second["allowed"]) == ("eve", "/admin/flag.txt", False)
