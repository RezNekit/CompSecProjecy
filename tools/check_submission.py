#!/usr/bin/env python3
"""Validate a fresh checkout and optionally build a reproducible submission archive."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ('server/server.py', 'server/auth.py', 'server/policy.py',
            'server/loader.py', 'server/audit.py', 'client/client.py',
            'data/users.json', 'data/user_roles.json', 'data/role_perms.csv',
            'data/mac_labels.json', 'data/dac_owners.csv', 'data/groups.json',
            'README.md', 'policy.md', 'CTF_writeup.pdf',
            'docs/evidence/wp5-results.md', 'docs/ai-disclosure.md',
            'tests/test_policy.py', 'tests/test_auth_loader.py',
            'tests/test_full_stack.py', '.github/workflows/tests.yml')


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def inspect_tree(root, tracked):
    problems = []
    for name in REQUIRED:
        if name not in tracked or not (root / name).is_file():
            problems.append('Missing tracked deliverable: ' + name)
    private_markers = [b'-----BEGIN ' + kind + b' PRIVATE KEY-----'
                       for kind in (b'OPENSSH', b'RSA', b'EC', b'DSA', b'ENCRYPTED')]
    private_markers.append(b'-----BEGIN ' + b'PRIVATE KEY-----')
    for name in tracked:
        path = root / name
        forbidden = (path.name in {'audit.jsonl', 'known_hosts', '.env'}
                     or 'ssh_host_' in path.name
                     or any(part in {'.venv', '__pycache__', '.pytest_cache', 'output'}
                            for part in Path(name).parts))
        if forbidden or path.is_symlink():
            problems.append('Runtime/secret file or symlink tracked: ' + name)
        if path.is_file() and any(marker in path.read_bytes() for marker in private_markers):
            problems.append('Private key content: ' + name)
    try:
        users = json.loads((root / 'data/users.json').read_text())
        for user in users:
            if any('password' in key.lower() and key != 'password_hash' for key in user):
                problems.append('Plaintext password field in users.json')
            base64.b64decode(user['salt'], validate=True)
            base64.b64decode(user['password_hash'], validate=True)
    except (OSError, ValueError, KeyError, TypeError):
        problems.append('Invalid authentication dataset')
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path)
    args = parser.parse_args()
    if git('status', '--porcelain').strip():
        print('Commit reviewed changes first: validation uses the committed tree.')
        return 1
    commit = git('rev-parse', 'HEAD').decode().strip()
    tracked = [x for x in git('ls-files', '-z').decode().split('\0') if x]
    problems = inspect_tree(ROOT, tracked)
    if problems:
        print('\n'.join(problems))
        return 1
    with tempfile.TemporaryDirectory(prefix='sftp-submission-') as temporary:
        clone = Path(temporary).resolve() / 'fresh'
        subprocess.run(['git', 'clone', '--quiet', '--no-local', str(ROOT), str(clone)], check=True)
        subprocess.run([sys.executable, '-m', 'pytest', '-q'], cwd=clone, check=True)
        if args.zip:
            destination = args.zip.resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            manifest = {'commit': commit, 'sha256': {
                name: hashlib.sha256((clone / name).read_bytes()).hexdigest()
                for name in tracked}}
            with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
                for name in tracked:
                    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, (clone / name).read_bytes())
                archive.writestr('SUBMISSION_MANIFEST.json', json.dumps(manifest, indent=2) + '\n')
            with zipfile.ZipFile(destination) as archive:
                assert archive.testzip() is None
                for name, digest in manifest['sha256'].items():
                    assert hashlib.sha256(archive.read(name)).hexdigest() == digest
            print(f'Created and verified {destination} (commit {commit})')
    print('Fresh-checkout tests and automated submission checks passed.')
    print('Human checks: group number, member disclosures, review and course upload.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
