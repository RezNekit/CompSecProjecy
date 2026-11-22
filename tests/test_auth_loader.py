"""WP2 acceptance tests: real salted hashes, lockout, audit and static data."""
import json
import logging
from pathlib import Path
import secrets
import sys

import pytest

import auth
import audit
import loader

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from make_users import create_user_record
from test_policy import make_policy


@pytest.fixture
def dataset(tmp_path):
    """Create independent users and all six policy/authentication data files."""
    make_policy(tmp_path)
    password = secrets.token_urlsafe(24)
    users = [create_user_record(name, password) for name in ('alice', 'bob', 'eve')]
    directory = tmp_path / 'data'
    (directory / 'users.json').write_text(json.dumps(users))
    return directory, password


@pytest.fixture
def authentication(dataset, tmp_path, monkeypatch):
    """Keep authentication time, audit output and failure delays isolated."""
    directory, password = dataset
    clock = [1000.0]
    monkeypatch.setattr(auth.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(auth.time, 'sleep', lambda delay: None)
    log = tmp_path / 'auth.jsonl'
    monkeypatch.setattr(auth, 'write_audit', lambda **record: audit.write_audit(**record, audit_path=log))
    return auth.AuthService(loader.load_users(directory)), password, clock, log


def test_password_verification_and_unknown_user(authentication, monkeypatch, caplog):
    """Right passwords pass, wrong/unknown credentials fail, and no password reaches logs."""
    service, password, _, log = authentication
    calls = []
    original = auth.hashlib.scrypt
    def spy(*args, **kwargs):
        calls.append(kwargs['salt'])
        return original(*args, **kwargs)
    monkeypatch.setattr(auth.hashlib, 'scrypt', spy)
    with caplog.at_level(logging.INFO):
        assert service.authenticate('bob', password) is True
        assert service.authenticate('bob', password + 'wrong') is False
        assert service.authenticate('unknown', password) is False
    assert len(calls) == 3  # Unknown usernames still incur a real hash.
    assert password not in log.read_text() + caplog.text
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r['allowed'] for r in records] == [True, False, False]
    assert all({'timestamp', 'user', 'op', 'path', 'allowed', 'reason'} <= r.keys() for r in records)


def test_lockout_and_expiry(authentication):
    """Five failures lock even a correct password until the five-minute lock expires."""
    service, password, clock, log = authentication
    for _ in range(auth.MAX_FAILS):
        assert service.authenticate('bob', 'wrong') is False
    assert service.authenticate('bob', password) is False
    clock[0] += auth.LOCK_SECONDS + 1
    assert service.authenticate('bob', password) is True
    assert any('locked' in json.loads(line)['reason'] for line in log.read_text().splitlines())


def test_failure_window_and_success_reset(authentication):
    """Expired failures and a successful login cannot trigger a later premature lockout."""
    service, password, clock, _ = authentication
    for _ in range(auth.MAX_FAILS - 1):
        assert not service.authenticate('bob', 'wrong')
    clock[0] += auth.WINDOW_SECONDS + 1
    assert not service.authenticate('bob', 'wrong')
    assert service.authenticate('bob', password)
    for _ in range(auth.MAX_FAILS - 1):
        assert not service.authenticate('bob', 'wrong')
    assert service.authenticate('bob', password)


def test_load_all_immutable_and_logged(dataset, caplog):
    """All static files load fully, announce counts and expose read-only structures."""
    directory, _ = dataset
    with caplog.at_level(logging.INFO):
        data = loader.load_all(directory)
    for path in directory.iterdir():
        assert path.name in caplog.text
    assert len(data['role_perms']) == 4
    assert len(data['dac_owners']) == 3
    with pytest.raises(TypeError):
        data['users']['bob']['n'] = 2
    with pytest.raises(TypeError):
        data['mac']['users']['bob'] = 'confidential'
    assert data['mac']['levels'] == ('public', 'internal', 'confidential')


@pytest.mark.parametrize('name', ['users.json', 'user_roles.json', 'groups.json',
                                  'mac_labels.json', 'role_perms.csv', 'dac_owners.csv'])
@pytest.mark.parametrize('damage', ['missing', 'malformed'])
def test_invalid_files_fail_cleanly(dataset, name, damage):
    """Every missing or malformed static file causes a readable configuration failure."""
    directory, _ = dataset
    path = directory / name
    if damage == 'missing':
        path.unlink()
    else:
        path.write_text('{invalid' if name.endswith('.json') else 'wrong,header\na,b,c\n')
    with pytest.raises(loader.DataError, match=name.replace('.', r'\.')):
        loader.load_all(directory)


@pytest.mark.parametrize('file,mutation', [
    ('user_roles.json', lambda x: {**x, 'mallory': ['guest']}),
    ('mac_labels.json', lambda x: {**x, 'users': {**x['users'], 'bob': 'unknown'}}),
    ('mac_labels.json', lambda x: {**x, 'levels': list(reversed(x['levels']))}),
    ('users.json', lambda x: [{**x[0], 'n': 3}, *x[1:]]),
])
def test_cross_reference_and_hash_validation(dataset, file, mutation):
    """Reject unknown subjects/clearances, reordered MAC levels and unsafe hash parameters."""
    directory, _ = dataset
    path = directory / file
    path.write_text(json.dumps(mutation(json.loads(path.read_text()))))
    with pytest.raises(loader.DataError):
        loader.load_all(directory)


def test_audit_control_characters_are_one_record(tmp_path):
    """Untrusted newlines cannot forge additional JSONL audit records."""
    path = tmp_path / 'audit.jsonl'
    audit.write_audit(user='eve\nadmin', op='read', path='/a\n/b', allowed=False,
                      reason='denied', audit_path=path)
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])['allowed'] is False


def test_audit_failure_denies_at_server_gate(tmp_path, monkeypatch):
    """An unwritable audit log prevents filesystem access even when policy otherwise allows."""
    import server as s
    from policy import Policy
    directory, _ = (tmp_path / 'data', None)
    make_policy(tmp_path)
    instance = Policy(directory, tmp_path)  # A directory cannot be opened as a JSONL file.
    session = s.SFTPSession(tmp_path, instance.authorize, instance.inherit)
    session.user = 'bob'
    with pytest.raises(PermissionError):
        session.check('write', '/projects/new')
