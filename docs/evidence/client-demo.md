# Client demo

This transcript is from 22 November 2026. The client ran in batch mode against
our server with the policy loaded from data/ and the CTF flag in place. At the
time, auth.py had not been added yet, so this particular demo used a fixed test
password for bob. It is not a test of the final password hashing or lockout.
Bob had the analyst role, internal clearance and membership of analysts. The
known_hosts file was temporary; its path is shortened below.

We tried all the required client commands, plus cd. After downloading the
file, we compared it with the upload using cmp and they matched. Bob could
not see admin in the root listing because he did not have permission to stat
it. We then tried a wrong password and a changed host key; both connections
were rejected, as shown below.

```text
$ python3 client/client.py --port 2222 --username bob --batch cmds.txt
The authenticity of host '127.0.0.1:2222' can't be established.
ED25519 key fingerprint is SHA256:1jiWDaxgNai1Xe+4kmJ+fQLpeA2lVwv1Sg4noC5UgQs.
Are you sure you want to continue connecting (yes/no)? Permanently added '127.0.0.1:2222' to client/known_hosts.
Connected to 127.0.0.1:2222 as bob. Type 'help'.
sftp> pwd
/
sftp> ls
drwxr-xr-x   3      501        0         96 Nov 22 12:52 projects
drwxr-xr-x   3      501        0         96 Nov 22 12:52 public
sftp> ls /projects
-rw-r--r--   1      501        0         32 Nov 22 12:52 plan.txt
sftp> mkdir /projects/demo
sftp> put notes.txt /projects/demo/notes.txt
Uploaded notes.txt -> /projects/demo/notes.txt (16 bytes)
sftp> stat /projects/demo/notes.txt
  File: /projects/demo/notes.txt
  Type: regular file
  Mode: -rw------- (0600)
  Size: 16 bytes
  Modified: 2026-11-22 12:52:42
sftp> get /projects/demo/notes.txt notes.copy.txt
Fetched /projects/demo/notes.txt -> notes.copy.txt (16 bytes)
sftp> cd /projects/demo
sftp> pwd
/projects/demo
sftp> ls
-rw-------   1      501        0         16 Nov 22 12:52 notes.txt
sftp> mkdir /admin/x
mkdir: permission denied
sftp> get /admin/ctf/flag.txt
get: permission denied
sftp> stat /projects/nope.txt
stat: no such file or directory
sftp> quit
(exit code 0)

$ python3 client/client.py --port 2222 --username bob --batch cmds.txt    # wrong password
Authentication failed (wrong username/password, or account locked).
(exit code 1)

$ python3 client/client.py --port 2222 --username bob --batch cmds.txt    # server now presents a different host key
WARNING: the host key for 127.0.0.1:2222 has CHANGED.
  Offered: SHA256:ZO3TWBAWSQKhpUvpFbeqBx/vTVped9Px3vx6nr5VLjA
  Pinned in client/known_hosts
Someone could be impersonating the server (man-in-the-middle), or the server key was regenerated. Connection aborted. If the change is expected, remove the old line from the known_hosts file.
(exit code 2)
```
