"""CTF: where the flag lives and which policy entries protect it.

setup_flag.py, run_attacks.py and the write-up take these values from here.
"""
FLAG = "FLAG{group01_sftp_wins}"
FLAG_PATH = "/admin/ctf/flag.txt"      # jail-relative POSIX path
FLAG_OWNER = "alice"

# The rows in data/ that keep the flag readable by alice alone. Together with
# layer 4 below they form four independent layers; bob and eve are each denied
# by every one of the first three.
REQUIRED_POLICY = {
    "role_perms.csv": [                    # layer 1, RBAC: only the admin role covers /admin
        "role,prefix,read,write,list,stat,mkdir",
        "admin,/,x,x,x,x,x",
        "analyst,/projects,x,x,x,x,x",     # no analyst or guest row reaches /admin
        "guest,/public,x,,x,x,",
    ],
    "mac_labels.json": {                   # layer 2, MAC: no read up, no write down
        "paths": {"/": "public", "/projects": "internal", "/admin": "confidential"},
        "users": {"alice": "confidential", "bob": "internal", "eve": "public"},
    },
    "dac_owners.csv": [                    # layer 3, DAC: owner-only directory
        "prefix,owner,group,mode",
        "/admin,alice,admins,0700",
    ],
}
# Layer 4 is the server's path handling: paths are canonicalized before the
# gate, every link is rejected, and files are opened with O_NOFOLLOW at use
# time, so a link cannot redirect a path.
