"""Integration contracts and startup failure checks."""
import subprocess
import sys
from pathlib import Path

import policy
from test_policy import make_policy

ROOT = Path(__file__).resolve().parents[1]


def test_public_policy_hooks(tmp_path, monkeypatch):
    """Server-facing policy hooks delegate to the configured policy instance."""
    instance = make_policy(tmp_path)
    monkeypatch.setattr(policy, 'current', instance)
    assert policy.authorize('bob', 'write', '/projects/new')[0] is True
    policy.inherit('bob', '/projects/new', 'file')
    assert instance.owners['/projects/new'][0] == 'bob'


def test_policy_missing_or_malformed_data(tmp_path):
    """Missing and malformed static policy files produce readable configuration errors."""
    import pytest
    with pytest.raises(policy.PolicyConfigError, match='cannot load'):
        policy.Policy(tmp_path, tmp_path / 'audit.jsonl')
    make_policy(tmp_path)
    (tmp_path / 'data/mac_labels.json').write_text('{broken')
    with pytest.raises(policy.PolicyConfigError, match='cannot load'):
        policy.Policy(tmp_path / 'data', tmp_path / 'audit.jsonl')


def test_invalid_startup_fails_cleanly(tmp_path):
    """Missing startup data yields a readable nonzero exit without a traceback."""
    result = subprocess.run([sys.executable, str(ROOT / 'server/server.py'),
                             '--data-dir', str(tmp_path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert 'users.json' in result.stderr
    assert 'Traceback' not in result.stderr
