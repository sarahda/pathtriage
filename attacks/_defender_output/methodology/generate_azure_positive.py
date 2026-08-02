#!/usr/bin/env python3
"""
PathTriage — Azure attack (positive) corpus generator.

Mirrors methodology/generate_positive.py for the Azure side. Emits the
control-plane and sign-in records an attacker's actions leave behind for
paths Z1-Z8, labelled with attack_id, step, and expected_primitive so the
harness can score against them.

Provenance
----------
Each sequence is derived from the corresponding first-party verification log
in attacks/Z*/verification_log.txt. Those logs record the attacker's own
output; this module renders the same actions as the Activity Log and Entra
sign-in records a defender would have. Where the log does not settle a field
(exact user agent, correlation id), the value is synthesised and marked in
the per-path comment below.

Determinism
-----------
Seeded, and --start-date and --version are required with no date-derived
defaults, so a run reproduces regardless of when it happens.

Usage
-----
    python3 generate_azure_positive.py \\
        --seed 42 --start-date 2026-06-30 --version 2026-08-02-1 \\
        --activity-output corpora/azure_activity_positive.jsonl \\
        --signin-output   corpora/azure_signin_positive.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

LOCATION = "australiaeast"

# The attacker operates from outside the VNet. The benign corpus anchors
# managed-identity traffic to VNET_IPS; these addresses are deliberately
# outside that set, which is the signal primitive 01 keys on.
ATTACKER_IPS = ["45.76.180.22", "45.76.180.23"]

# Benign VNet egress, reused here so cross-VM steps look internally consistent
VNET_IPS = ["20.53.100.10", "20.53.100.11"]

ATTACKER_UA = "python-requests/2.31.0"
AZ_CLI_UA   = "AzureCLI/2.58.0 (MSI) Python/3.11.7 Linux"


def gen_hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def gen_guid(rng: random.Random) -> str:
    h = gen_hex(rng, 32)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def activity(
    rng: random.Random, ts: datetime, sub: str, rg: str,
    operation: str, resource_id: str,
    caller: str, caller_type: str, caller_oid: str,
    caller_ip: str, ua: str,
    attack_id: str, step: int, expected_primitive: str,
    version: str, seed: int, result: str = "Success",
    properties: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "properties": properties or {},
        "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operationName": operation,
        "category": "Administrative",
        "resultType": result,
        "resultSignature": "Succeeded.OK" if result == "Success" else "Failed.Forbidden",
        "correlationId": gen_guid(rng),
        "eventDataId": gen_guid(rng),
        "level": "Informational",
        "location": LOCATION,
        "callerIpAddress": caller_ip,
        "caller": caller,
        "userAgent": ua,
        "resourceId": resource_id,
        "resourceGroupName": rg,
        "subscriptionId": sub,
        "identity": {
            "authorization": {
                "scope": f"/subscriptions/{sub}",
                "action": operation,
                "evidence": {"role": "Contributor", "roleAssignmentScope": f"/subscriptions/{sub}"},
            },
            "claims": {
                "oid": caller_oid,
                "appid": caller_oid if caller_type != "User" else None,
                "idtyp": "app" if caller_type != "User" else "user",
                "name": caller,
            },
            "type": caller_type,
        },
        "pathtriage": {
            "attack_id": attack_id,
            "step": step,
            "expected_primitive": expected_primitive,
            "corpus_version": version,
            "generator_seed": seed,
            "stream": "activity",
        },
    }


def signin(
    rng: random.Random, ts: datetime, tenant: str,
    principal: str, oid: str, ptype: str, ip: str,
    attack_id: str, step: int, expected_primitive: str,
    version: str, seed: int,
    resource: str = "https://management.azure.com/",
) -> Dict[str, Any]:
    return {
        "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "category": "ServicePrincipalSignInLogs" if ptype != "User" else "SignInLogs",
        "operationName": "Sign-in activity",
        "resultType": "0",
        "resultDescription": "Success",
        "correlationId": gen_guid(rng),
        "identity": principal,
        "tenantId": tenant,
        "location": LOCATION,
        "properties": {
            "id": gen_guid(rng),
            "servicePrincipalId": oid if ptype != "User" else None,
            "servicePrincipalName": principal if ptype != "User" else None,
            "userPrincipalName": None,
            "appId": oid if ptype != "User" else None,
            "ipAddress": ip,
            "resourceDisplayName": "Windows Azure Service Management API",
            "resourceIdentity": resource,
            "authenticationProtocol": (
                "clientCredentials" if ptype == "ServicePrincipal"
                else "managedIdentity" if ptype == "ManagedIdentity"
                else "interactive"
            ),
            "tokenIssuerType": "AzureAD",
            "conditionalAccessStatus": "notApplied",
        },
        "pathtriage": {
            "attack_id": attack_id,
            "step": step,
            # Sign-in records are corroborating context that the primitives
            # join against, not rows a primitive returns. The detection
            # target is the Activity Log event, so these carry no
            # expected_primitive and are not scored as missed detections.
            "expected_primitive": None,
            "corpus_version": version,
            "generator_seed": seed,
            "stream": "signin",
        },
    }


def build(
    rng: random.Random, sub: str, tenant: str, base: datetime,
    version: str, seed: int,
) -> Tuple[List[Dict], List[Dict]]:
    """Return (activity_events, signin_events) for Z1-Z8."""
    acts: List[Dict] = []
    sigs: List[Dict] = []
    rg = "pathtriage-rg"

    def rid(provider: str, rtype: str, name: str) -> str:
        return (f"/subscriptions/{sub}/resourceGroups/{rg}"
                f"/providers/{provider}/{rtype}/{name}")

    # -----------------------------------------------------------------------
    # Z1 — VM managed identity via IMDS, token used off-VM
    #      primitive 01. Log: token acquired, then subscription-scope reads
    #      from an address outside the VNet.
    # -----------------------------------------------------------------------
    t = base + timedelta(hours=3, minutes=12)
    mi_z1 = gen_guid(rng)
    ip = ATTACKER_IPS[0]
    sigs.append(signin(rng, t, tenant, "mi-pathtriage-z1", mi_z1, "ManagedIdentity",
                       ip, "Z1", 1, "01", version, seed))
    acts.append(activity(rng, t + timedelta(seconds=8), sub, rg,
                         "Microsoft.Resources/subscriptions/read",
                         f"/subscriptions/{sub}",
                         "mi-pathtriage-z1", "ManagedIdentity", mi_z1, ip, ATTACKER_UA,
                         "Z1", 2, "01", version, seed))
    acts.append(activity(rng, t + timedelta(seconds=21), sub, rg,
                         "Microsoft.Compute/virtualMachines/read",
                         rid("Microsoft.Compute", "virtualMachines", "pathtriage-z1-vm"),
                         "mi-pathtriage-z1", "ManagedIdentity", mi_z1, ip, ATTACKER_UA,
                         "Z1", 3, "01", version, seed))
    acts.append(activity(rng, t + timedelta(seconds=34), sub, rg,
                         "Microsoft.Authorization/roleAssignments/read",
                         f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments",
                         "mi-pathtriage-z1", "ManagedIdentity", mi_z1, ip, ATTACKER_UA,
                         "Z1", 4, "01", version, seed))

    # -----------------------------------------------------------------------
    # Z2 — SP credential theft from App Service config, then SP sign-in
    #      primitive 04. Log: MI reads site config, then a new SP appears.
    # -----------------------------------------------------------------------
    t = base + timedelta(days=1, hours=2, minutes=41)
    mi_z2 = gen_guid(rng)
    sp_z2 = gen_guid(rng)
    acts.append(activity(rng, t, sub, rg,
                         "Microsoft.Web/sites/config/list/action",
                         rid("Microsoft.Web", "sites", "pathtriage-z2-app"),
                         "mi-pathtriage-z2", "ManagedIdentity", mi_z2,
                         VNET_IPS[0], AZ_CLI_UA, "Z2", 1, "04", version, seed))
    sigs.append(signin(rng, t + timedelta(minutes=2), tenant, "sp-pathtriage-z2",
                       sp_z2, "ServicePrincipal", ATTACKER_IPS[0],
                       "Z2", 2, "04", version, seed))
    acts.append(activity(rng, t + timedelta(minutes=2, seconds=15), sub, rg,
                         "Microsoft.Resources/subscriptions/resourceGroups/write",
                         f"/subscriptions/{sub}/resourceGroups/{rg}",
                         "sp-pathtriage-z2", "ServicePrincipal", sp_z2,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z2", 3, "04", version, seed))

    # -----------------------------------------------------------------------
    # Z3 — Role assignment manipulation (self-grant Owner on RG)
    #      primitive 02. Log: roleAssignments/write naming the caller.
    # -----------------------------------------------------------------------
    t = base + timedelta(days=2, hours=5, minutes=7)
    mi_z3 = gen_guid(rng)
    acts.append(activity(rng, t, sub, rg,
                         "Microsoft.Authorization/roleAssignments/write",
                         f"/subscriptions/{sub}/resourceGroups/{rg}"
                         f"/providers/Microsoft.Authorization/roleAssignments/{gen_guid(rng)}",
                         "mi-pathtriage-z3", "ManagedIdentity", mi_z3,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z3", 1, "02", version, seed,
                         properties={"principalId": mi_z3}))
    acts.append(activity(rng, t + timedelta(seconds=48), sub, rg,
                         "Microsoft.Resources/subscriptions/resourceGroups/write",
                         f"/subscriptions/{sub}/resourceGroups/{rg}",
                         "mi-pathtriage-z3", "ManagedIdentity", mi_z3,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z3", 2, "02", version, seed))

    # -----------------------------------------------------------------------
    # Z4 — Custom role definition abuse (wildcard injection)
    #      primitive 03. Log: roleDefinitions/write, then a write exercising
    #      the mutated role. Per Finding 2 the mutation only persists when the
    #      caller already holds the injected actions; the sequence below is
    #      the Owner arm, which persists.
    # -----------------------------------------------------------------------
    t = base + timedelta(days=3, hours=1, minutes=55)
    mi_z4 = gen_guid(rng)
    acts.append(activity(rng, t, sub, rg,
                         "Microsoft.Authorization/roleDefinitions/write",
                         f"/subscriptions/{sub}/providers/Microsoft.Authorization"
                         f"/roleDefinitions/{gen_guid(rng)}",
                         "mi-pathtriage-z4", "ManagedIdentity", mi_z4,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z4", 1, "03", version, seed))
    # Fresh token after mutation (D-Z4-03: mutated permissions do not
    # propagate to tokens already issued)
    sigs.append(signin(rng, t + timedelta(seconds=12), tenant, "mi-pathtriage-z4",
                       mi_z4, "ManagedIdentity", ATTACKER_IPS[0],
                       "Z4", 2, "03", version, seed))
    acts.append(activity(rng, t + timedelta(seconds=20), sub, rg,
                         "Microsoft.Resources/tags/write",
                         f"/subscriptions/{sub}/resourceGroups/{rg}"
                         f"/providers/Microsoft.Resources/tags/default",
                         "mi-pathtriage-z4", "ManagedIdentity", mi_z4,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z4", 3, "03", version, seed))

    # -----------------------------------------------------------------------
    # Z5 — Key Vault secret escalation
    #      primitive 04. Log: secret read by an MI, then an SP sign-in using
    #      the credential that was in the secret.
    # -----------------------------------------------------------------------
    t = base + timedelta(days=4, hours=4, minutes=18)
    mi_z5 = gen_guid(rng)
    sp_z5 = gen_guid(rng)
    acts.append(activity(rng, t, sub, rg,
                         "Microsoft.KeyVault/vaults/secrets/read",
                         rid("Microsoft.KeyVault", "vaults", "kv-pathtriage-z5"),
                         "mi-pathtriage-z5", "ManagedIdentity", mi_z5,
                         VNET_IPS[0], AZ_CLI_UA, "Z5", 1, "04", version, seed))
    sigs.append(signin(rng, t + timedelta(minutes=1, seconds=30), tenant,
                       "sp-pathtriage-z5", sp_z5, "ServicePrincipal",
                       ATTACKER_IPS[1], "Z5", 2, "04", version, seed))
    acts.append(activity(rng, t + timedelta(minutes=1, seconds=52), sub, rg,
                         "Microsoft.Compute/virtualMachines/write",
                         rid("Microsoft.Compute", "virtualMachines", "pathtriage-z5-vm"),
                         "sp-pathtriage-z5", "ServicePrincipal", sp_z5,
                         ATTACKER_IPS[1], ATTACKER_UA, "Z5", 3, "04", version, seed))

    # -----------------------------------------------------------------------
    # Z6 — Storage account key abuse
    #      primitive 04. Log: listKeys from an unexpected source. Per
    #      Finding 3 the subsequent shared-key data-plane access does not
    #      appear in the Activity Log at all, which is the point: the
    #      control-plane event is the only observable.
    # -----------------------------------------------------------------------
    t = base + timedelta(days=5, hours=2, minutes=33)
    mi_z6 = gen_guid(rng)
    acts.append(activity(rng, t, sub, rg,
                         "Microsoft.Storage/storageAccounts/listKeys/action",
                         rid("Microsoft.Storage", "storageAccounts", "stpathtriagez6"),
                         "mi-pathtriage-z6", "ManagedIdentity", mi_z6,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z6", 1, "04", version, seed))
    # The tfstate parsed out of the blob yields SP credentials
    sp_z6 = gen_guid(rng)
    sigs.append(signin(rng, t + timedelta(minutes=4), tenant, "sp-pathtriage-z6",
                       sp_z6, "ServicePrincipal", ATTACKER_IPS[0],
                       "Z6", 2, "04", version, seed))
    acts.append(activity(rng, t + timedelta(minutes=4, seconds=25), sub, rg,
                         "Microsoft.Resources/subscriptions/resourceGroups/write",
                         f"/subscriptions/{sub}/resourceGroups/{rg}",
                         "sp-pathtriage-z6", "ServicePrincipal", sp_z6,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z6", 3, "04", version, seed))

    # -----------------------------------------------------------------------
    # Z7 — MI/SP role cascade
    #      primitive 05. Log: SP-A grants a role to SP-B, then SP-B signs in
    #      and writes. Per D-Z7-03 the grant takes 30-60s to reach the token
    #      validation layer, so the gap below is part of the signature.
    # -----------------------------------------------------------------------
    t = base + timedelta(days=6, hours=3, minutes=2)
    sp_a = gen_guid(rng)
    sp_b = gen_guid(rng)
    acts.append(activity(rng, t, sub, rg,
                         "Microsoft.Authorization/roleAssignments/write",
                         f"/subscriptions/{sub}/providers/Microsoft.Authorization"
                         f"/roleAssignments/{gen_guid(rng)}",
                         "sp-pathtriage-z7a", "ServicePrincipal", sp_a,
                         ATTACKER_IPS[1], ATTACKER_UA, "Z7", 1, "05", version, seed,
                         properties={"principalId": sp_b}))
    sigs.append(signin(rng, t + timedelta(seconds=52), tenant, "sp-pathtriage-z7b",
                       sp_b, "ServicePrincipal", ATTACKER_IPS[1],
                       "Z7", 2, "05", version, seed))
    acts.append(activity(rng, t + timedelta(seconds=68), sub, rg,
                         "Microsoft.Resources/subscriptions/resourceGroups/write",
                         f"/subscriptions/{sub}/resourceGroups/{rg}",
                         "sp-pathtriage-z7b", "ServicePrincipal", sp_b,
                         ATTACKER_IPS[1], ATTACKER_UA, "Z7", 3, "05", version, seed))

    # -----------------------------------------------------------------------
    # Z8 — VM RunCommand token exfiltration
    #      primitive 01. Log: runCommand by MI-A, then MI-B's token used from
    #      an address that is not VM-B's. Timings follow the verification log
    #      (202 accepted, ~10s to succeeded).
    # -----------------------------------------------------------------------
    t = base + timedelta(days=6, hours=7, minutes=44)
    mi_a = gen_guid(rng)
    mi_b = gen_guid(rng)
    sigs.append(signin(rng, t, tenant, "mi-pathtriage-z8a", mi_a, "ManagedIdentity",
                       ATTACKER_IPS[0], "Z8", 1, "01", version, seed))
    acts.append(activity(rng, t + timedelta(seconds=6), sub, rg,
                         "Microsoft.Compute/virtualMachines/runCommand/action",
                         rid("Microsoft.Compute", "virtualMachines", "pathtriage-z8-vm-b"),
                         "mi-pathtriage-z8a", "ManagedIdentity", mi_a,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z8", 2, "01", version, seed))
    # MI-B's token is read from inside VM-B, so the sign-in looks internal...
    sigs.append(signin(rng, t + timedelta(seconds=14), tenant, "mi-pathtriage-z8b",
                       mi_b, "ManagedIdentity", VNET_IPS[1],
                       "Z8", 3, "01", version, seed))
    # ...but is then used from the attacker's address, which is the signal
    acts.append(activity(rng, t + timedelta(seconds=31), sub, rg,
                         "Microsoft.Resources/tags/write",
                         f"/subscriptions/{sub}/resourceGroups/{rg}"
                         f"/providers/Microsoft.Resources/tags/default",
                         "mi-pathtriage-z8b", "ManagedIdentity", mi_b,
                         ATTACKER_IPS[0], ATTACKER_UA, "Z8", 4, "01", version, seed))

    acts.sort(key=lambda e: e["time"])
    sigs.sort(key=lambda e: e["time"])
    return acts, sigs


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate the Azure attack corpus for Z1-Z8.")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--subscription-id", default="adc6db82-4cf4-4460-a335-891df5190199")
    p.add_argument("--tenant-id", default="e8c547f6-1717-4e2c-a1cb-11c95f063f13")
    p.add_argument("--start-date", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--activity-output", type=Path, required=True)
    p.add_argument("--signin-output", type=Path, required=True)
    return p.parse_args()


def main() -> int:
    a = parse_args()
    rng = random.Random(a.seed)
    base = datetime.fromisoformat(a.start_date).replace(tzinfo=timezone.utc)

    acts, sigs = build(rng, a.subscription_id, a.tenant_id, base, a.version, a.seed)

    a.activity_output.parent.mkdir(parents=True, exist_ok=True)
    a.signin_output.parent.mkdir(parents=True, exist_ok=True)

    ah, sh = hashlib.sha256(), hashlib.sha256()
    with open(a.activity_output, "wb") as f:
        for e in acts:
            line = (json.dumps(e, separators=(",", ":"), sort_keys=True) + "\n").encode()
            f.write(line); ah.update(line)
    with open(a.signin_output, "wb") as f:
        for e in sigs:
            line = (json.dumps(e, separators=(",", ":"), sort_keys=True) + "\n").encode()
            f.write(line); sh.update(line)

    paths = sorted({e["pathtriage"]["attack_id"] for e in acts + sigs})
    print("=" * 72)
    print("PathTriage Azure attack corpus")
    print("=" * 72)
    print(f"  paths           : {len(paths)}  ({', '.join(paths)})")
    print(f"  activity events : {len(acts)}")
    print(f"  sign-in events  : {len(sigs)}")
    print(f"  total           : {len(acts) + len(sigs)}")
    print(f"  activity sha256 : {ah.hexdigest()}")
    print(f"  signin   sha256 : {sh.hexdigest()}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
