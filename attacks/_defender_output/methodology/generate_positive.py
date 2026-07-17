#!/usr/bin/env python3
"""
PathTriage Positive Corpus Generator
====================================

Specification: attacks/_defender_output/methodology/evaluation_protocol.md §1.1

Emits a CloudTrail Lake JSON Lines corpus modelling the 8 verified AWS
attack labs. Each event is labelled with pathtriage.attack_id (P1..P8),
pathtriage.step (attack step index), and pathtriage.expected_primitive
(01..05) for TP/FP scoring.

The events reproduce the CloudTrail-visible portion of each exploit.
Web-layer events (e.g. the SSRF request itself in P2) are omitted because
they are not CloudTrail-observable; the primitive detects the downstream
credential misuse.

Convergence mapping (per root README):
    P1 PassRole + RunInstances      → primitive 01 (IMDS)
    P2 IMDS SSRF Credential Theft   → primitive 01 (IMDS)
    P3 CreatePolicyVersion Escal.   → primitive 03 (IAM mod mutate)
    P4 AssumeRole Chain             → primitive 05 (trust topology)
    P5 AttachPolicy Escalation      → primitive 02 (IAM mod assign)
    P6 EC2 Instance Profile Abuse   → primitive 01 (IMDS)
    P7 Lambda Env-Var Cred Theft    → primitive 04 (credential discovery)
    P8 S3 Credential Harvest        → primitive 04 (credential discovery)

Usage:
    python generate_positive.py \\
        --output ../evaluation/corpora/positive_corpus.jsonl \\
        --account-id 559292738121 \\
        --start-date 2026-07-07T20:00:00
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

REGION = "ap-southeast-2"

# Attacker persona (external, off-band)
ATTACKER_IP     = "185.220.101.42"           # off-band, not in baseline IP pools
ATTACKER_UA     = "python-requests/2.31.0"   # curl/requests-style, not SDK
ATTACKER_USER   = "pathtriage-low-priv-attacker"
ATTACKER_PID    = "AIDAATTACKER0000000"

# Attack infra (created by exploits)
ATTACK_INSTANCE = "i-1234567890abcdef0"
ATTACK_ROLE_ADMIN     = "pathtriage-passrole-admin"
ATTACK_ROLE_CHAIN_R1  = "pathtriage-chain-role-1"
ATTACK_ROLE_CHAIN_R2  = "pathtriage-chain-role-admin"
ATTACK_INSTANCE_P6    = "i-fedcba0987654321a"
ATTACK_LAMBDA         = "pathtriage-lambda-vuln"
ATTACK_BUCKET         = "pathtriage-victim-terraform-state"

# Long-term IAM key exfiltrated in P7/P8 (attacker uses it from off-band)
EXFILTRATED_ACCESS_KEY = "AKIAEXFILTRATED00000"


# ===========================================================================
# Event builder — identical schema to generate_baseline.py
# ===========================================================================

def gen_hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def gen_id(rng: random.Random) -> str:
    h = gen_hex(rng, 32)
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def iam_user_identity(user_name: str, principal_id: str, account_id: str,
                      access_key: str = None) -> Dict[str, Any]:
    ident = {
        "type":        "IAMUser",
        "principalId": principal_id,
        "arn":         f"arn:aws:iam::{account_id}:user/{user_name}",
        "accountId":   account_id,
        "userName":    user_name,
    }
    if access_key:
        ident["accessKeyId"] = access_key
    return ident


def assumed_role_identity(role_name: str, session_name: str, account_id: str,
                          creation_date: datetime) -> Dict[str, Any]:
    role_pid = "AROA" + "".join(role_name.upper().replace("-", "")[:17].ljust(17, "X"))
    return {
        "type":        "AssumedRole",
        "principalId": f"{role_pid}:{session_name}",
        "arn":         f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}",
        "accountId":   account_id,
        "sessionContext": {
            "attributes": {
                "creationDate":     creation_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mfaAuthenticated": "false",
            },
            "sessionIssuer": {
                "type":        "Role",
                "principalId": role_pid,
                "arn":         f"arn:aws:iam::{account_id}:role/{role_name}",
                "accountId":   account_id,
                "userName":    role_name,
            },
        },
    }


def make_event(
    rng: random.Random,
    event_time: datetime,
    event_source: str,
    event_name: str,
    user_identity: Dict[str, Any],
    source_ip: str,
    user_agent: str,
    account_id: str,
    corpus_version: str,
    attack_id: str,
    step: int,
    expected_primitive: str,
    request_parameters: Dict[str, Any] = None,
    response_elements: Any = None,
) -> Dict[str, Any]:
    return {
        "eventVersion":       "1.09",
        "userIdentity":       user_identity,
        "eventTime":          event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource":        event_source,
        "eventName":          event_name,
        "awsRegion":          REGION,
        "sourceIPAddress":    source_ip,
        "userAgent":          user_agent,
        "requestParameters":  request_parameters if request_parameters is not None else {},
        "responseElements":   response_elements,
        "requestID":          gen_id(rng),
        "eventID":            gen_id(rng),
        "eventType":          "AwsApiCall",
        "recipientAccountId": account_id,
        "pathtriage": {
            "corpus_version":     corpus_version,
            "category":           "attack",
            "attack_id":          attack_id,
            "step":               step,
            "expected_primitive": expected_primitive,
        },
    }


# ===========================================================================
# Attack path event sequences
# ===========================================================================

def build_p1_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P1: PassRole + RunInstances.
    Attacker launches EC2 with admin instance profile, then credentials
    from that instance are used from an unexpected source (attacker off-box).
    Primitive 01 catches IMDS-role use with IP anomaly."""
    events = []
    attacker_ident = iam_user_identity(ATTACKER_USER, ATTACKER_PID, account_id)

    # Step 1: RunInstances with IAM instance profile — visible in CloudTrail
    events.append(make_event(
        rng, t0, "ec2.amazonaws.com", "RunInstances",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P1", 1, "01",
        request_parameters={
            "instanceType": "t3.micro",
            "imageId": "ami-" + gen_hex(rng, 17),
            "iamInstanceProfile": {"name": f"{ATTACK_ROLE_ADMIN}-profile"},
            "minCount": 1, "maxCount": 1,
        },
    ))

    # Step 2: Instance boots, gets creds via IMDS (not in CloudTrail)
    # Step 3: Attacker uses instance creds off-box — primitive 01 fires here
    sess = ATTACK_INSTANCE
    role_ident = assumed_role_identity(
        ATTACK_ROLE_ADMIN, sess, account_id, t0 + timedelta(seconds=30),
    )
    events.append(make_event(
        rng, t0 + timedelta(seconds=45), "sts.amazonaws.com", "GetCallerIdentity",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P1", 2, "01",
    ))
    events.append(make_event(
        rng, t0 + timedelta(seconds=60), "iam.amazonaws.com", "ListRoles",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P1", 3, "01",
    ))
    return events


def build_p2_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P2: IMDS SSRF Credential Theft.
    Web-layer SSRF exploit is not CloudTrail-observable. What IS observable
    is subsequent use of the extracted creds from the attacker's own IP."""
    events = []
    compromised_instance = "i-0abcdef1234567890"
    role_ident = assumed_role_identity(
        "webapp-role", compromised_instance, account_id, t0 - timedelta(minutes=5),
    )
    # Step 1: cred use from attacker off-box IP
    events.append(make_event(
        rng, t0, "sts.amazonaws.com", "GetCallerIdentity",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P2", 1, "01",
    ))
    events.append(make_event(
        rng, t0 + timedelta(seconds=15), "s3.amazonaws.com", "ListBuckets",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P2", 2, "01",
    ))
    events.append(make_event(
        rng, t0 + timedelta(seconds=30), "iam.amazonaws.com", "GetUser",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P2", 3, "01",
    ))
    return events


def build_p3_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P3: CreatePolicyVersion Escalation.
    Attacker with iam:CreatePolicyVersion on a self-attached customer-managed
    policy rewrites the policy to grant admin. Primitive 03 catches this."""
    events = []
    attacker_ident = iam_user_identity(ATTACKER_USER, ATTACKER_PID, account_id)
    policy_arn = f"arn:aws:iam::{account_id}:policy/pathtriage-self-mut-policy"

    # Step 1: recon
    events.append(make_event(
        rng, t0, "iam.amazonaws.com", "GetPolicy",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P3", 1, "03",
        request_parameters={"policyArn": policy_arn},
    ))
    # Step 2: rewrite policy to admin — primitive 03 fires
    events.append(make_event(
        rng, t0 + timedelta(seconds=10), "iam.amazonaws.com", "CreatePolicyVersion",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P3", 2, "03",
        request_parameters={
            "policyArn": policy_arn,
            "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
            "setAsDefault": True,
        },
    ))
    # Step 3: exercise admin
    events.append(make_event(
        rng, t0 + timedelta(seconds=25), "iam.amazonaws.com", "ListUsers",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P3", 3, "03",
    ))
    return events


def build_p4_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P4: AssumeRole Chain.
    User → R1 → R2(admin). Two AssumeRole hops in short succession from
    the same lineage. Primitive 05 catches chained sts:AssumeRole."""
    events = []
    attacker_ident = iam_user_identity(ATTACKER_USER, ATTACKER_PID, account_id)

    # Step 1: attacker assumes R1
    events.append(make_event(
        rng, t0, "sts.amazonaws.com", "AssumeRole",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P4", 1, "05",
        request_parameters={
            "roleArn": f"arn:aws:iam::{account_id}:role/{ATTACK_ROLE_CHAIN_R1}",
            "roleSessionName": "chain-r1",
        },
    ))
    # Step 2: R1 session assumes R2 — primitive 05 fires on chain
    r1_ident = assumed_role_identity(
        ATTACK_ROLE_CHAIN_R1, "chain-r1", account_id, t0,
    )
    events.append(make_event(
        rng, t0 + timedelta(seconds=8), "sts.amazonaws.com", "AssumeRole",
        r1_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P4", 2, "05",
        request_parameters={
            "roleArn": f"arn:aws:iam::{account_id}:role/{ATTACK_ROLE_CHAIN_R2}",
            "roleSessionName": "chain-r2",
        },
    ))
    # Step 3: exercise R2 admin
    r2_ident = assumed_role_identity(
        ATTACK_ROLE_CHAIN_R2, "chain-r2", account_id, t0 + timedelta(seconds=8),
    )
    events.append(make_event(
        rng, t0 + timedelta(seconds=20), "iam.amazonaws.com", "ListUsers",
        r2_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P4", 3, "05",
    ))
    return events


def build_p5_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P5: AttachPolicy Escalation.
    Attacker with iam:AttachUserPolicy self-attaches AdministratorAccess.
    Primitive 02 catches self-assignment IAM mod."""
    events = []
    attacker_ident = iam_user_identity(ATTACKER_USER, ATTACKER_PID, account_id)

    # Step 1: recon
    events.append(make_event(
        rng, t0, "iam.amazonaws.com", "ListAttachedUserPolicies",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P5", 1, "02",
        request_parameters={"userName": ATTACKER_USER},
    ))
    # Step 2: self AttachUserPolicy AdminAccess — primitive 02 fires
    events.append(make_event(
        rng, t0 + timedelta(seconds=12), "iam.amazonaws.com", "AttachUserPolicy",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P5", 2, "02",
        request_parameters={
            "userName":  ATTACKER_USER,
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    ))
    return events


def build_p6_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P6: EC2 Instance Profile Abuse.
    Attacker with prior shell on an EC2 reads IMDS creds and uses them
    off-box. IMDS read not in CloudTrail; off-box use is."""
    events = []
    sess = ATTACK_INSTANCE_P6
    role_ident = assumed_role_identity(
        "app-worker-role", sess, account_id, t0 - timedelta(minutes=10),
    )
    # Step 1: cred used from attacker off-box IP + UA
    events.append(make_event(
        rng, t0, "sts.amazonaws.com", "GetCallerIdentity",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P6", 1, "01",
    ))
    events.append(make_event(
        rng, t0 + timedelta(seconds=20), "s3.amazonaws.com", "ListBuckets",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P6", 2, "01",
    ))
    events.append(make_event(
        rng, t0 + timedelta(seconds=35), "ec2.amazonaws.com", "DescribeInstances",
        role_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P6", 3, "01",
    ))
    return events


def build_p7_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P7: Lambda Env-Var Credential Theft.
    Attacker enumerates Lambda funcs, reads env vars (contains AKIA key),
    uses key off-band. Primitive 04 catches surface-API read + off-band use."""
    events = []
    attacker_ident = iam_user_identity(ATTACKER_USER, ATTACKER_PID, account_id)

    # Step 1: recon
    events.append(make_event(
        rng, t0, "lambda.amazonaws.com", "ListFunctions",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P7", 1, "04",
    ))
    # Step 2: GetFunctionConfiguration surfaces env vars — primitive 04 fires
    events.append(make_event(
        rng, t0 + timedelta(seconds=8), "lambda.amazonaws.com", "GetFunctionConfiguration",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P7", 2, "04",
        request_parameters={"functionName": ATTACK_LAMBDA},
    ))
    # Step 3: exfiltrated AKIA key used off-band
    exfil_ident = iam_user_identity(
        "burdened-service-user", "AIDABURDENEDSVCUSR00", account_id,
        access_key=EXFILTRATED_ACCESS_KEY,
    )
    events.append(make_event(
        rng, t0 + timedelta(seconds=30), "sts.amazonaws.com", "GetCallerIdentity",
        exfil_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P7", 3, "04",
    ))
    return events


def build_p8_events(rng, t0, account_id, corpus_version) -> List[Dict[str, Any]]:
    """P8: S3 Credential Harvest.
    Attacker enumerates buckets, reads .tfstate that contains AKIA key,
    uses key off-band. Primitive 04 catches surface-API read + off-band use."""
    events = []
    attacker_ident = iam_user_identity(ATTACKER_USER, ATTACKER_PID, account_id)

    # Step 1: recon
    events.append(make_event(
        rng, t0, "s3.amazonaws.com", "ListBuckets",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P8", 1, "04",
    ))
    # Step 2: GetObject on .tfstate — primitive 04 fires (surface API read)
    events.append(make_event(
        rng, t0 + timedelta(seconds=10), "s3.amazonaws.com", "GetObject",
        attacker_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P8", 2, "04",
        request_parameters={
            "bucketName": ATTACK_BUCKET,
            "key":        "terraform.tfstate",
        },
    ))
    # Step 3: exfiltrated AKIA key used off-band
    exfil_ident = iam_user_identity(
        "burdened-tfstate-user", "AIDABURDENEDTFSTATE0", account_id,
        access_key=EXFILTRATED_ACCESS_KEY,
    )
    events.append(make_event(
        rng, t0 + timedelta(seconds=45), "sts.amazonaws.com", "GetCallerIdentity",
        exfil_ident, ATTACKER_IP, ATTACKER_UA,
        account_id, corpus_version, "P8", 3, "04",
    ))
    return events


# ===========================================================================
# Main
# ===========================================================================

ATTACK_BUILDERS = {
    "P1": build_p1_events,
    "P2": build_p2_events,
    "P3": build_p3_events,
    "P4": build_p4_events,
    "P5": build_p5_events,
    "P6": build_p6_events,
    "P7": build_p7_events,
    "P8": build_p8_events,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate positive-corpus CloudTrail events for PathTriage attack labs."
    )
    p.add_argument("--seed",       type=int, default=42)
    p.add_argument("--account-id", type=str, default="559292738121")
    p.add_argument("--start-date", type=str, default="2026-07-07T20:00:00",
                   help="First attack timestamp (UTC ISO). Attacks are staggered ~15 min apart.")
    p.add_argument("--output",     type=Path, default=Path("positive_corpus.jsonl"))
    p.add_argument("--version",    type=str, default=None)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    rng = random.Random(args.seed)
    corpus_version = args.version or (datetime.now(timezone.utc).strftime("%Y-%m-%d") + "-pos-1")

    t0 = datetime.fromisoformat(args.start_date).replace(tzinfo=timezone.utc)

    all_events: List[Dict[str, Any]] = []
    per_attack_stats: List[Tuple[str, str, int]] = []

    for i, (attack_id, builder) in enumerate(ATTACK_BUILDERS.items()):
        # Stagger attacks 15 min apart
        attack_start = t0 + timedelta(minutes=15 * i)
        events = builder(rng, attack_start, args.account_id, corpus_version)
        all_events.extend(events)
        primitive = events[0]["pathtriage"]["expected_primitive"]
        per_attack_stats.append((attack_id, primitive, len(events)))

    all_events.sort(key=lambda e: e["eventTime"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    with open(args.output, "wb") as fh:
        for evt in all_events:
            line = (json.dumps(evt, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
            fh.write(line)
            hasher.update(line)

    print("=" * 72, file=sys.stderr)
    print("PathTriage positive corpus generation", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print(f"  attacks    : {len(ATTACK_BUILDERS)}", file=sys.stderr)
    print(f"  events     : {len(all_events)}", file=sys.stderr)
    print(f"  start      : {t0.isoformat()}", file=sys.stderr)
    print(f"  version    : {corpus_version}", file=sys.stderr)
    print(f"  output     : {args.output}", file=sys.stderr)
    print(f"  sha256     : {hasher.hexdigest()}", file=sys.stderr)
    print("-" * 72, file=sys.stderr)
    print("  attack     primitive   events", file=sys.stderr)
    for attack_id, primitive, n in per_attack_stats:
        print(f"  {attack_id:10s} {primitive:11s} {n}", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
