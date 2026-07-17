"""Fixture-based enumerator — offline inventory from JSON.

Used for offline testing (`pathtriage discover --fixture path/to/inv.json`)
and for the demo video walkthrough where a live AWS scan is not desired.
The JSON schema matches the IamInventory dataclass shape.
"""
from __future__ import annotations

import json
from pathlib import Path

from pathtriage.enumerators.aws import IamEntity, IamInventory


def load_fixture(fixture_path: str) -> IamInventory:
    data = json.loads(Path(fixture_path).read_text())
    inv = IamInventory()
    inv.policies = dict(data.get("policies", {}))
    for u in data.get("users", []):
        inv.users.append(IamEntity(
            name=u["name"], kind="user", arn=u["arn"],
            attached_policy_arns=list(u.get("attached_policy_arns", [])),
            inline_policy_names=list(u.get("inline_policy_names", [])),
        ))
    for r in data.get("roles", []):
        inv.roles.append(IamEntity(
            name=r["name"], kind="role", arn=r["arn"],
            attached_policy_arns=list(r.get("attached_policy_arns", [])),
            inline_policy_names=list(r.get("inline_policy_names", [])),
        ))
    return inv
