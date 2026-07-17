"""Tests for the fixture-based offline enumerator."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pathtriage.enumerators.fixture import load_fixture


def test_load_fixture_produces_populated_inventory():
    data = {
        "policies": {"arn:aws:iam::aws:policy/AdministratorAccess": "AdministratorAccess"},
        "users": [{
            "name": "alice",
            "arn":  "arn:aws:iam::111111111111:user/alice",
            "attached_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "inline_policy_names": [],
        }],
        "roles": [],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        fname = fh.name
    try:
        inv = load_fixture(fname)
    finally:
        Path(fname).unlink()

    assert not inv.is_empty()
    assert len(inv.users) == 1
    assert inv.users[0].name == "alice"
    assert inv.users[0].attached_policy_arns == ["arn:aws:iam::aws:policy/AdministratorAccess"]


def test_load_catalogue_fixture_end_to_end():
    """End-to-end: load committed sample fixture, verify structure."""
    fixture_path = Path("pathtriage/fixtures/aws_catalogue_sample.json")
    if not fixture_path.exists():
        return  # skip if not installed as pkg data
    inv = load_fixture(str(fixture_path))
    assert not inv.is_empty()
    assert any(u.name == "pathtriage-low-priv-attacker" for u in inv.users)
    assert any(r.name == "pathtriage-passrole-admin" for r in inv.roles)
