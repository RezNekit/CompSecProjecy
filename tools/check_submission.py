#!/usr/bin/env python3
"""Inspect tracked deliverables and optionally create a secret-filtered submission zip."""
import argparse
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ('server/server.py', 'server/auth.py', 'server/policy.py',
            'server/loader.py', 'server/audit.py', 'client/client.py',
            'data/users.json', 'data/user_roles.json', 'data/role_perms.csv',
            'data/mac_labels.json', 'data/dac_owners.csv', 'README.md',
            'policy.md', 'CTF_writeup.pdf', 'docs/evidence/wp5-results.md',
            'docs/ai-disclosure.md')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, help='Build only after checks and tests pass')
    args = parser.parse_args()
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    tracked = [name for name in tracked if name]
    problems = []
    for name in REQUIRED:
        if not (ROOT / name).is_file():
            problems.append('Missing: ' + name)
        elif name not in tracked:
            problems.append('Not tracked (missing from fresh clone): ' + name)
    for name in tracked:
        path = ROOT / name
        forbidden = (Path(name).name in {'audit.jsonl', 'known_hosts', '.env'}
                     or 'ssh_host_' in name or '.venv' in Path(name).parts)
        if forbidden:
            problems.append('Runtime/secret file tracked: ' + name)
        if path.is_file() and path.stat().st_size < 2_000_000:
            content = path.read_bytes()
            if b'-----BEGIN OPENSSH PRIVATE KEY-----' in content or b'-----BEGIN PRIVATE KEY-----' in content:
                problems.append('Private key content: ' + name)
    if problems:
        print('\n'.join(problems))
        return 1
    subprocess.run([sys.executable, '-m', 'pytest', '-q'], cwd=ROOT, check=True)
    if args.zip:
        dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip()
        if dirty:
            print('Commit the reviewed changes before creating the final archive.')
            return 1
        args.zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.zip, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name in tracked:
                archive.write(ROOT / name, name)
        print('Created ' + str(args.zip))
    print('Automated checks passed. Manual disclosure, credential and OS review still required.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
