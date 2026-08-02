#!/usr/bin/env python3
"""
PathTriage — Azure benign baseline corpus generator.

Mirrors methodology/generate_baseline.py (AWS) for the Azure side. Produces
two correlated streams, because Azure splits across sources that the AWS
equivalent keeps in one:

  * Activity Log   — control-plane operations (resource writes, listKeys,
                     role assignments, role definitions, runCommand)
  * Entra sign-in  — service-principal and managed-identity token issuance

Finding 6 in the Technical Report is precisely that Azure needs a join across
these two streams where AWS needs one log. The generator therefore emits both
with consistent identities, timestamps and IP anchors, so that a detection
query which joins them has something coherent to join.

Determinism
-----------
All sampling derives from a single seeded random.Random. Running twice with
identical --seed, --start-date and --version produces byte-identical output.
Unlike the AWS generator, --start-date and --version have no date-derived
defaults: both are required, so a run is reproducible regardless of when it
happens.

Usage
-----
    python3 generate_azure_baseline.py \\
        --rate 100000 --days 7 --seed 42 \\
        --start-date 2026-06-30 --version 2026-08-02-1 \\
        --activity-output corpora/azure_activity_baseline.jsonl \\
        --signin-output   corpora/azure_signin_baseline.jsonl
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
from zoneinfo import ZoneInfo

# ===========================================================================
# Category shares
#
# Mirrors the AWS split in spirit: a long read-heavy tail, a large automated
# deployment share, storage traffic, a small administrative slice, and compute
# lifecycle. Proportions are matched to the AWS generator so that the two
# corpora are comparable in shape; the operations themselves are Azure's.
# ===========================================================================

CATEGORY_SHARES: Dict[str, float] = {
    "read_heavy_browse":    0.40,   # portal / CLI reads
    "cicd_deployment":      0.25,   # SP-driven deployments
    "storage_access":       0.15,   # blob + listKeys
    "rbac_admin":           0.08,   # role assignment / definition writes
    "compute_lifecycle":    0.07,   # VM start/stop/runCommand
    "long_tail":            0.05,   # everything else
}

LOCATION = "australiaeast"

# ===========================================================================
# Operation pools  (operationName, resource_type, weight)
# ===========================================================================

READ_OPERATIONS: List[Tuple[str, str, int]] = [
    ("Microsoft.Compute/virtualMachines/read",              "virtualMachines",   30),
    ("Microsoft.Storage/storageAccounts/read",              "storageAccounts",   22),
    ("Microsoft.Resources/subscriptions/resourceGroups/read","resourceGroups",   18),
    ("Microsoft.Web/sites/read",                            "sites",             12),
    ("Microsoft.KeyVault/vaults/read",                      "vaults",             8),
    ("Microsoft.Network/virtualNetworks/read",              "virtualNetworks",    6),
    ("Microsoft.Authorization/roleAssignments/read",        "roleAssignments",    4),
]

DEPLOY_OPERATIONS: List[Tuple[str, str, int]] = [
    ("Microsoft.Web/sites/config/write",                    "sites",             28),
    ("Microsoft.Web/sites/write",                           "sites",             20),
    ("Microsoft.Resources/deployments/write",               "deployments",       18),
    ("Microsoft.Web/sites/restart/action",                  "sites",             14),
    ("Microsoft.ContainerRegistry/registries/push/write",   "registries",        12),
    ("Microsoft.Web/sites/slotsswap/action",                "sites",              8),
]

STORAGE_OPERATIONS: List[Tuple[str, str, int]] = [
    ("Microsoft.Storage/storageAccounts/blobServices/containers/read",
                                                            "storageAccounts",   40),
    ("Microsoft.Storage/storageAccounts/listKeys/action",   "storageAccounts",   25),
    ("Microsoft.Storage/storageAccounts/blobServices/write","storageAccounts",   20),
    ("Microsoft.Storage/storageAccounts/write",             "storageAccounts",   15),
]

RBAC_OPERATIONS: List[Tuple[str, str, int]] = [
    ("Microsoft.Authorization/roleAssignments/write",       "roleAssignments",   45),
    ("Microsoft.Authorization/roleAssignments/delete",      "roleAssignments",   25),
    ("Microsoft.Authorization/roleDefinitions/write",       "roleDefinitions",   20),
    ("Microsoft.Authorization/roleDefinitions/delete",      "roleDefinitions",   10),
]

COMPUTE_OPERATIONS: List[Tuple[str, str, int]] = [
    ("Microsoft.Compute/virtualMachines/start/action",      "virtualMachines",   30),
    ("Microsoft.Compute/virtualMachines/deallocate/action", "virtualMachines",   28),
    ("Microsoft.Compute/virtualMachines/restart/action",    "virtualMachines",   18),
    ("Microsoft.Compute/virtualMachines/runCommand/action", "virtualMachines",   14),
    ("Microsoft.Compute/virtualMachines/write",             "virtualMachines",   10),
]

LONG_TAIL_OPERATIONS: List[Tuple[str, str, int]] = [
    ("Microsoft.Insights/metrics/read",                     "metrics",           25),
    ("Microsoft.OperationalInsights/workspaces/read",       "workspaces",        20),
    ("Microsoft.KeyVault/vaults/secrets/read",              "vaults",            18),
    ("Microsoft.Network/networkSecurityGroups/read",        "networkSecurityGroups", 15),
    ("Microsoft.Sql/servers/databases/read",                "databases",         12),
    ("Microsoft.Advisor/recommendations/read",              "recommendations",   10),
]

# ===========================================================================
# Identity anchors
#
# The evaluation depends on baseline joins, so identities must recur with
# stable properties: the same operator signs in from the same handful of
# addresses, the same deployment principal uses the same egress range.
# ===========================================================================

HUMAN_OPERATORS: List[Tuple[str, str]] = [
    ("alice.engineer",  "User"),
    ("bob.platform",    "User"),
    ("carol.sre",       "User"),
    ("dan.data",        "User"),
    ("erin.security",   "User"),
    ("frank.devops",    "User"),
    ("grace.analyst",   "User"),
    ("henry.support",   "User"),
]

CICD_PRINCIPALS = ["sp-github-deploy", "sp-azdo-release"]

APP_MANAGED_IDENTITIES = ["mi-app-api", "mi-app-worker", "mi-app-batch"]

STORAGE_ACCOUNTS = ["stappdata01", "stapplogs01", "stappbackup01"]
KEY_VAULTS       = ["kv-app-prod", "kv-app-staging"]
WEB_APPS         = ["app-api-prod", "app-api-staging", "app-worker-prod"]

# IP anchors — the detection queries treat departure from these as anomalous
HOME_IPS   = ["203.0.113." + str(i) for i in range(1, 13)]
OFFICE_IPS = ["198.51.100.10", "198.51.100.20", "198.51.100.30"]
CICD_IPS   = ["192.0.2.100", "192.0.2.101", "192.0.2.102"]
VNET_IPS   = ["20.53.100.10", "20.53.100.11"]      # australiaeast VNet egress
AZURE_INTERNAL = "Azure Internal"

PORTAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AzurePortal"
CLI_UAS = [
    "AzureCLI/2.58.0 (MSI) Python/3.11.7 Linux",
    "AzureCLI/2.57.0 (MSI) Python/3.11.6 Darwin",
    "AzurePowerShell/Az.11.2.0",
]
CICD_UA = "AzureCLI/2.58.0 (MSI) Python/3.11.8 Linux-5.15.0-azure"
MI_UA   = "Microsoft.Azure.Management/1.0 (ManagedIdentity)"


# ===========================================================================
# Primitives
# ===========================================================================

def gen_hex(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def gen_guid(rng: random.Random) -> str:
    h = gen_hex(rng, 32)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def weighted_pick(rng: random.Random, items: List[Tuple[Any, ...]]) -> Tuple[Any, ...]:
    total = sum(i[-1] for i in items)
    r = rng.uniform(0, total)
    upto = 0.0
    for item in items:
        upto += item[-1]
        if r <= upto:
            return item
    return items[-1]


def sample_biz_weighted_timestamp(
    rng: random.Random, day_start_utc: datetime, tz: ZoneInfo
) -> datetime:
    """Business-hours weighted: ~75% inside 09:00-18:00 local, weekdays heavier."""
    local_day = day_start_utc.astimezone(tz)
    is_weekend = local_day.weekday() >= 5
    if is_weekend:
        hour = rng.choice([10, 11, 14, 15, 20, 21, 22])
    elif rng.random() < 0.75:
        hour = rng.choices(
            [9, 10, 11, 12, 13, 14, 15, 16, 17],
            weights=[8, 14, 15, 10, 8, 12, 14, 12, 7],
        )[0]
    else:
        hour = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 18, 19, 20, 21, 22, 23])
    local_ts = local_day.replace(
        hour=hour, minute=rng.randrange(60), second=rng.randrange(60), microsecond=0
    )
    return local_ts.astimezone(timezone.utc)


def sample_uniform_timestamp(rng: random.Random, day_start_utc: datetime) -> datetime:
    return day_start_utc + timedelta(seconds=rng.randrange(86400))


def cicd_burst_timestamps(
    rng: random.Random, day_start_utc: datetime, tz: ZoneInfo, budget: int
) -> List[datetime]:
    """Deployment bursts: clustered runs during business hours, as CI/CD is."""
    local_day = day_start_utc.astimezone(tz)
    if local_day.weekday() >= 5:
        n_bursts = rng.randrange(0, 2)
    else:
        n_bursts = rng.randrange(4, 7)
    stamps: List[datetime] = []
    for _ in range(n_bursts):
        hour = rng.choice([9, 10, 11, 13, 14, 15, 16, 17])
        base = local_day.replace(hour=hour, minute=rng.randrange(60), second=0, microsecond=0)
        for _ in range(rng.randrange(40, 120)):
            offset = timedelta(seconds=rng.randrange(0, 900))
            stamps.append((base + offset).astimezone(timezone.utc))
    rng.shuffle(stamps)
    return stamps[:budget]


# ===========================================================================
# Record builders
# ===========================================================================

def make_activity_event(
    rng: random.Random,
    ts: datetime,
    subscription_id: str,
    operation: str,
    resource_type: str,
    resource_name: str,
    rg_name: str,
    caller: str,
    caller_type: str,
    caller_oid: str,
    caller_ip: str,
    user_agent: str,
    corpus_version: str,
    seed: int,
    result: str = "Success",
    properties: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """One Azure Activity Log record, in the shape the ARM API returns."""
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
        "userAgent": user_agent,
        "resourceId": (
            f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}"
            f"/providers/Microsoft.{resource_type.split('/')[0] if '/' in resource_type else 'Resources'}"
            f"/{resource_type}/{resource_name}"
        ),
        "resourceGroupName": rg_name,
        "subscriptionId": subscription_id,
        "identity": {
            "authorization": {
                "scope": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}",
                "action": operation,
                "evidence": {"role": "Contributor", "roleAssignmentScope": f"/subscriptions/{subscription_id}"},
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
            "category": "",          # filled by caller
            "corpus_version": corpus_version,
            "generator_seed": seed,
            "stream": "activity",
        },
    }


def make_signin_event(
    rng: random.Random,
    ts: datetime,
    tenant_id: str,
    principal_name: str,
    principal_oid: str,
    principal_type: str,
    ip: str,
    corpus_version: str,
    seed: int,
    resource: str = "https://management.azure.com/",
) -> Dict[str, Any]:
    """One Entra sign-in record, correlating with an Activity Log operation."""
    return {
        "time": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "category": "ServicePrincipalSignInLogs" if principal_type != "User" else "SignInLogs",
        "operationName": "Sign-in activity",
        "resultType": "0",
        "resultDescription": "Success",
        "correlationId": gen_guid(rng),
        "identity": principal_name,
        "tenantId": tenant_id,
        "location": LOCATION,
        "properties": {
            "id": gen_guid(rng),
            "servicePrincipalId": principal_oid if principal_type != "User" else None,
            "servicePrincipalName": principal_name if principal_type != "User" else None,
            "userPrincipalName": f"{principal_name}@contoso.onmicrosoft.com" if principal_type == "User" else None,
            "appId": principal_oid if principal_type != "User" else None,
            "ipAddress": ip,
            "resourceDisplayName": "Windows Azure Service Management API",
            "resourceIdentity": resource,
            "authenticationProtocol": (
                "clientCredentials" if principal_type == "ServicePrincipal"
                else "managedIdentity" if principal_type == "ManagedIdentity"
                else "interactive"
            ),
            "tokenIssuerType": "AzureAD",
            "conditionalAccessStatus": "notApplied",
        },
        "pathtriage": {
            "corpus_version": corpus_version,
            "generator_seed": seed,
            "stream": "signin",
        },
    }


# ===========================================================================
# Category builders
# ===========================================================================

def build_oid_map(rng: random.Random) -> Dict[str, str]:
    """Stable object IDs, so baseline joins have something to anchor on."""
    oids: Dict[str, str] = {}
    for name, _ in HUMAN_OPERATORS:
        oids[name] = gen_guid(rng)
    for name in CICD_PRINCIPALS + APP_MANAGED_IDENTITIES:
        oids[name] = gen_guid(rng)
    return oids


def build_vm_pool(rng: random.Random, count: int = 20) -> List[str]:
    return [f"vm-app-{gen_hex(rng, 6)}" for _ in range(count)]


def pick_human(rng: random.Random) -> Tuple[str, str, str]:
    """Returns (name, ip, user_agent) with a stable-ish home/office split."""
    name, _ = rng.choice(HUMAN_OPERATORS)
    if rng.random() < 0.6:
        ip = rng.choice(OFFICE_IPS)
    else:
        ip = rng.choice(HOME_IPS)
    ua = PORTAL_UA if rng.random() < 0.45 else rng.choice(CLI_UAS)
    return name, ip, ua


def compute_daily_budgets(rate: int) -> Dict[str, int]:
    return {cat: int(round(rate * share)) for cat, share in CATEGORY_SHARES.items()}


# ===========================================================================
# Main generation
# ===========================================================================

def generate(
    rate: int,
    days: int,
    seed: int,
    subscription_id: str,
    tenant_id: str,
    timezone_name: str,
    corpus_version: str,
    start_date: datetime,
    activity_path: Path,
    signin_path: Path,
) -> Tuple[int, int, str, str]:
    rng = random.Random(seed)
    tz = ZoneInfo(timezone_name)

    oids = build_oid_map(rng)
    vm_pool = build_vm_pool(rng)
    budgets = compute_daily_budgets(rate)

    rgs = ["rg-app-prod", "rg-app-staging", "rg-platform", "rg-data"]

    act_hash = hashlib.sha256()
    sig_hash = hashlib.sha256()
    act_count = sig_count = 0

    with open(activity_path, "wb") as af, open(signin_path, "wb") as sf:

        def emit_activity(ev: Dict[str, Any], category: str) -> None:
            nonlocal act_count
            ev["pathtriage"]["category"] = category
            line = (json.dumps(ev, separators=(",", ":"), sort_keys=True) + "\n").encode()
            af.write(line)
            act_hash.update(line)
            act_count += 1

        def emit_signin(ev: Dict[str, Any]) -> None:
            nonlocal sig_count
            line = (json.dumps(ev, separators=(",", ":"), sort_keys=True) + "\n").encode()
            sf.write(line)
            sig_hash.update(line)
            sig_count += 1

        for day_idx in range(days):
            day_start = start_date + timedelta(days=day_idx)

            # --- 1. Read-heavy browsing -------------------------------------
            for _ in range(budgets["read_heavy_browse"]):
                ts = sample_biz_weighted_timestamp(rng, day_start, tz)
                name, ip, ua = pick_human(rng)
                op, rtype, _ = weighted_pick(rng, READ_OPERATIONS)
                emit_activity(make_activity_event(
                    rng, ts, subscription_id, op, rtype,
                    rng.choice(vm_pool) if rtype == "virtualMachines" else rng.choice(STORAGE_ACCOUNTS),
                    rng.choice(rgs), name, "User", oids[name], ip, ua,
                    corpus_version, seed,
                ), "read_heavy_browse")

            # --- 2. CI/CD deployment ----------------------------------------
            stamps = cicd_burst_timestamps(rng, day_start, tz, budgets["cicd_deployment"])
            # Group into coherent deployment sessions
            per_session = max(1, len(stamps) // max(1, len(stamps) // 60 or 1))
            sp = rng.choice(CICD_PRINCIPALS)
            sp_ip = rng.choice(CICD_IPS)
            for idx, ts in enumerate(stamps):
                if idx % per_session == 0:
                    sp = rng.choice(CICD_PRINCIPALS)
                    sp_ip = rng.choice(CICD_IPS)
                    # Each deployment session begins with a token request
                    emit_signin(make_signin_event(
                        rng, ts, tenant_id, sp, oids[sp], "ServicePrincipal",
                        sp_ip, corpus_version, seed,
                    ))
                op, rtype, _ = weighted_pick(rng, DEPLOY_OPERATIONS)
                emit_activity(make_activity_event(
                    rng, ts, subscription_id, op, rtype,
                    rng.choice(WEB_APPS), rng.choice(rgs),
                    sp, "ServicePrincipal", oids[sp], sp_ip, CICD_UA,
                    corpus_version, seed,
                ), "cicd_deployment")
            # Diffuse remainder
            for _ in range(max(0, budgets["cicd_deployment"] - len(stamps))):
                ts = sample_biz_weighted_timestamp(rng, day_start, tz)
                sp = rng.choice(CICD_PRINCIPALS)
                op, rtype, _ = weighted_pick(rng, DEPLOY_OPERATIONS)
                emit_activity(make_activity_event(
                    rng, ts, subscription_id, op, rtype,
                    rng.choice(WEB_APPS), rng.choice(rgs),
                    sp, "ServicePrincipal", oids[sp], rng.choice(CICD_IPS), CICD_UA,
                    corpus_version, seed,
                ), "cicd_deployment")

            # --- 3. Storage access ------------------------------------------
            for _ in range(budgets["storage_access"]):
                ts = sample_uniform_timestamp(rng, day_start)
                op, rtype, _ = weighted_pick(rng, STORAGE_OPERATIONS)
                # listKeys is mostly done by app managed identities from the VNet
                if op.endswith("listKeys/action") and rng.random() < 0.8:
                    mi = rng.choice(APP_MANAGED_IDENTITIES)
                    emit_signin(make_signin_event(
                        rng, ts, tenant_id, mi, oids[mi], "ManagedIdentity",
                        rng.choice(VNET_IPS), corpus_version, seed,
                        resource="https://storage.azure.com/",
                    ))
                    emit_activity(make_activity_event(
                        rng, ts, subscription_id, op, rtype,
                        rng.choice(STORAGE_ACCOUNTS), rng.choice(rgs),
                        mi, "ManagedIdentity", oids[mi],
                        rng.choice(VNET_IPS), MI_UA, corpus_version, seed,
                    ), "storage_access")
                else:
                    name, ip, ua = pick_human(rng)
                    emit_activity(make_activity_event(
                        rng, ts, subscription_id, op, rtype,
                        rng.choice(STORAGE_ACCOUNTS), rng.choice(rgs),
                        name, "User", oids[name], ip, ua, corpus_version, seed,
                    ), "storage_access")

            # --- 4. RBAC administration -------------------------------------
            for _ in range(budgets["rbac_admin"]):
                ts = sample_biz_weighted_timestamp(rng, day_start, tz)
                name, ip, ua = pick_human(rng)
                op, rtype, _ = weighted_pick(rng, RBAC_OPERATIONS)
                # Benign grants go to established application identities.
                grantee = oids[rng.choice(APP_MANAGED_IDENTITIES + CICD_PRINCIPALS)]
                emit_activity(make_activity_event(
                    rng, ts, subscription_id, op, rtype,
                    gen_guid(rng), rng.choice(rgs),
                    name, "User", oids[name], ip, ua, corpus_version, seed,
                    properties={"principalId": grantee} if "roleAssignments" in op else {},
                ), "rbac_admin")

            # --- 5. Compute lifecycle ---------------------------------------
            for _ in range(budgets["compute_lifecycle"]):
                ts = sample_biz_weighted_timestamp(rng, day_start, tz)
                op, rtype, _ = weighted_pick(rng, COMPUTE_OPERATIONS)
                # runCommand is an operator action, from operator addresses
                if op.endswith("runCommand/action"):
                    name, ip, ua = pick_human(rng)
                    emit_activity(make_activity_event(
                        rng, ts, subscription_id, op, rtype,
                        rng.choice(vm_pool), rng.choice(rgs),
                        name, "User", oids[name], ip, ua, corpus_version, seed,
                    ), "compute_lifecycle")
                else:
                    name, ip, ua = pick_human(rng)
                    emit_activity(make_activity_event(
                        rng, ts, subscription_id, op, rtype,
                        rng.choice(vm_pool), rng.choice(rgs),
                        name, "User", oids[name], ip, ua, corpus_version, seed,
                    ), "compute_lifecycle")

            # --- 6. Long tail -----------------------------------------------
            for _ in range(budgets["long_tail"]):
                ts = sample_uniform_timestamp(rng, day_start)
                op, rtype, _ = weighted_pick(rng, LONG_TAIL_OPERATIONS)
                if rng.random() < 0.5:
                    mi = rng.choice(APP_MANAGED_IDENTITIES)
                    emit_activity(make_activity_event(
                        rng, ts, subscription_id, op, rtype,
                        rng.choice(KEY_VAULTS), rng.choice(rgs),
                        mi, "ManagedIdentity", oids[mi],
                        rng.choice(VNET_IPS), MI_UA, corpus_version, seed,
                    ), "long_tail")
                else:
                    name, ip, ua = pick_human(rng)
                    emit_activity(make_activity_event(
                        rng, ts, subscription_id, op, rtype,
                        rng.choice(KEY_VAULTS), rng.choice(rgs),
                        name, "User", oids[name], ip, ua, corpus_version, seed,
                    ), "long_tail")

            # --- Daily managed-identity token issuance ----------------------
            # App MIs request tokens throughout the day from inside the VNet.
            # These are the benign analogue of Z1/Z8 token use.
            for _ in range(rate // 50):
                ts = sample_uniform_timestamp(rng, day_start)
                mi = rng.choice(APP_MANAGED_IDENTITIES)
                emit_signin(make_signin_event(
                    rng, ts, tenant_id, mi, oids[mi], "ManagedIdentity",
                    rng.choice(VNET_IPS), corpus_version, seed,
                ))

            # Human interactive sign-ins
            for _ in range(rate // 200):
                ts = sample_biz_weighted_timestamp(rng, day_start, tz)
                name, ip, _ = pick_human(rng)
                emit_signin(make_signin_event(
                    rng, ts, tenant_id, name, oids[name], "User",
                    ip, corpus_version, seed,
                ))

    return act_count, sig_count, act_hash.hexdigest(), sig_hash.hexdigest()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate a synthetic Azure Activity Log + Entra sign-in baseline corpus."
    )
    p.add_argument("--rate", type=int, default=100000, help="Activity events per day.")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--subscription-id", default="adc6db82-4cf4-4460-a335-891df5190199")
    p.add_argument("--tenant-id", default="e8c547f6-1717-4e2c-a1cb-11c95f063f13")
    p.add_argument("--timezone", default="Australia/Sydney")
    p.add_argument("--start-date", required=True,
                   help="Corpus start date, ISO (e.g. 2026-06-30). Required: no date-derived default.")
    p.add_argument("--version", required=True,
                   help="Corpus version tag. Required: no date-derived default.")
    p.add_argument("--activity-output", type=Path, required=True)
    p.add_argument("--signin-output", type=Path, required=True)
    return p.parse_args()


def main() -> int:
    a = parse_args()
    start = datetime.fromisoformat(a.start_date).replace(tzinfo=timezone.utc)

    a.activity_output.parent.mkdir(parents=True, exist_ok=True)
    a.signin_output.parent.mkdir(parents=True, exist_ok=True)

    bar = "=" * 72
    print(bar)
    print("PathTriage Azure baseline corpus generation")
    print(bar)
    print(f"  rate            : {a.rate:,} activity events/day")
    print(f"  days            : {a.days}")
    print(f"  seed            : {a.seed}")
    print(f"  timezone        : {a.timezone}")
    print(f"  start_date      : {start.isoformat()}")
    print(f"  version         : {a.version}")
    print(f"  category mix    : {CATEGORY_SHARES}")
    print("-" * 72)

    act_n, sig_n, act_sha, sig_sha = generate(
        rate=a.rate, days=a.days, seed=a.seed,
        subscription_id=a.subscription_id, tenant_id=a.tenant_id,
        timezone_name=a.timezone, corpus_version=a.version,
        start_date=start,
        activity_path=a.activity_output, signin_path=a.signin_output,
    )

    print("-" * 72)
    print(f"  activity events : {act_n:,}")
    print(f"  sign-in events  : {sig_n:,}")
    print(f"  activity sha256 : {act_sha}")
    print(f"  signin   sha256 : {sig_sha}")
    print(bar)
    print("  → record both hashes in evaluation_report.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
