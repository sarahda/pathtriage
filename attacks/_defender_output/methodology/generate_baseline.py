#!/usr/bin/env python3
"""
PathTriage Synthetic Baseline CloudTrail Corpus Generator
=========================================================

Specification: attacks/_defender_output/methodology/baseline_generation.md
Consumed by:   attacks/_defender_output/methodology/evaluation_protocol.md

Generates a synthetic CloudTrail Lake JSON Lines corpus representing benign
enterprise activity for evaluating detection primitive false-positive rates.

Design guarantees:
  - Reproducibility: same (rate, days, seed) tuple produces byte-for-byte
    identical output. A SHA-256 hash is emitted after generation for the
    reference-corpus verification (spec §3.3).
  - Anchoring: principal identities, resource ARNs, and IP addresses persist
    across the corpus so baseline-join queries in primitives have historical
    anchors (spec §1).
  - Realism (bounded): event names, response codes, userIdentity structure,
    and resource ARNs conform to the CloudTrail schema. Realism is bounded
    by synthetic origin — see evaluation_protocol.md §5.1.

Usage:
    python generate_baseline.py --rate 100000 --days 7 --seed 42 \\
        --output baseline_corpus.jsonl

    # Sensitivity analysis corpora:
    python generate_baseline.py --rate 10000  --days 7 --seed 42 \\
        --output baseline_10k.jsonl
    python generate_baseline.py --rate 1000000 --days 7 --seed 42 \\
        --output baseline_1M.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from zoneinfo import ZoneInfo
except ImportError:
    print("Python 3.9+ required (zoneinfo module).", file=sys.stderr)
    sys.exit(2)


# ===========================================================================
# Category shares (spec §2.2 — canonical)
# ===========================================================================

CATEGORY_SHARES: Dict[str, float] = {
    "read_heavy_browse":    0.40,
    "cicd_role_assumption": 0.25,
    "s3_access":            0.15,
    "devops_iam":           0.08,
    "ec2_lifecycle":        0.07,
    "long_tail":            0.05,
}

REGION = "ap-southeast-2"


# ===========================================================================
# Action pools
# ===========================================================================

# (event_name, event_source, weight)
READ_HEAVY_ACTIONS: List[Tuple[str, str, int]] = [
    ("DescribeInstances",       "ec2.amazonaws.com",                     25),
    ("ListBuckets",             "s3.amazonaws.com",                      15),
    ("ListRoles",               "iam.amazonaws.com",                     12),
    ("GetPolicy",               "iam.amazonaws.com",                     10),
    ("DescribeLoadBalancers",   "elasticloadbalancing.amazonaws.com",     8),
    ("ListFunctions",           "lambda.amazonaws.com",                   7),
    ("DescribeSecurityGroups",  "ec2.amazonaws.com",                      5),
    ("DescribeVpcs",            "ec2.amazonaws.com",                      4),
    ("GetBucketPolicy",         "s3.amazonaws.com",                       3),
    ("ListUsers",               "iam.amazonaws.com",                      3),
    ("DescribeStacks",          "cloudformation.amazonaws.com",           3),
    ("ListTables",              "dynamodb.amazonaws.com",                 2),
    ("DescribeTable",           "dynamodb.amazonaws.com",                 2),
    ("GetItem",                 "dynamodb.amazonaws.com",                 1),
]

CICD_DEPLOY_STEPS: List[Tuple[str, str]] = [
    # Ordered inside a burst
    ("sts.amazonaws.com",             "AssumeRole"),
    ("cloudformation.amazonaws.com",  "DescribeStacks"),
    ("cloudformation.amazonaws.com",  "CreateChangeSet"),
    ("cloudformation.amazonaws.com",  "ExecuteChangeSet"),
    ("s3.amazonaws.com",              "PutObject"),
    ("s3.amazonaws.com",              "PutObject"),
    ("s3.amazonaws.com",              "PutObject"),
    ("lambda.amazonaws.com",          "UpdateFunctionCode"),
    ("lambda.amazonaws.com",          "PublishVersion"),
    ("cloudformation.amazonaws.com",  "DescribeStackEvents"),
]

# Per-day fixed rates (spec §4.3) — FP-critical IAM writes
DEVOPS_IAM_WRITES: List[Tuple[str, str, int]] = [
    # (event_name, event_source, per-day rate)
    ("CreateRole",           "iam.amazonaws.com", 2),
    ("AttachRolePolicy",     "iam.amazonaws.com", 5),
    ("PutRolePolicy",        "iam.amazonaws.com", 3),
    ("CreatePolicyVersion",  "iam.amazonaws.com", 1),  # sharpest FP challenge for primitive 03
]

DEVOPS_IAM_READS: List[Tuple[str, str]] = [
    ("iam.amazonaws.com", "GetUser"),
    ("iam.amazonaws.com", "GetRole"),
    ("iam.amazonaws.com", "ListAttachedRolePolicies"),
    ("iam.amazonaws.com", "SimulatePrincipalPolicy"),
    ("iam.amazonaws.com", "ListRolePolicies"),
    ("iam.amazonaws.com", "GetRolePolicy"),
    ("iam.amazonaws.com", "ListPolicies"),
]

# Per-day fixed rates (spec §4.5) — EC2 lifecycle-write events
EC2_LIFECYCLE_WRITES: List[Tuple[str, str, int]] = [
    ("RunInstances",           "ec2.amazonaws.com", 80),
    ("TerminateInstances",     "ec2.amazonaws.com", 60),
    ("AttachInstanceProfile",  "ec2.amazonaws.com", 10),
]

EC2_LIFECYCLE_MISC: List[Tuple[str, str]] = [
    ("ec2.amazonaws.com", "DescribeInstanceStatus"),
    ("ec2.amazonaws.com", "CreateTags"),
    ("ec2.amazonaws.com", "CreateSecurityGroup"),
    ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress"),
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("ec2.amazonaws.com", "DescribeVolumes"),
]

LONG_TAIL_ACTIONS: List[Tuple[str, str]] = [
    ("kms.amazonaws.com",                  "Decrypt"),
    ("kms.amazonaws.com",                  "GenerateDataKey"),
    ("kms.amazonaws.com",                  "DescribeKey"),
    ("kms.amazonaws.com",                  "ListKeys"),
    ("secretsmanager.amazonaws.com",       "GetSecretValue"),
    ("secretsmanager.amazonaws.com",       "DescribeSecret"),
    ("secretsmanager.amazonaws.com",       "ListSecrets"),
    ("lambda.amazonaws.com",               "Invoke"),
    ("lambda.amazonaws.com",               "GetFunction"),
    ("cloudwatch.amazonaws.com",           "PutMetricData"),
    ("cloudwatch.amazonaws.com",           "GetMetricStatistics"),
    ("logs.amazonaws.com",                 "PutLogEvents"),
    ("logs.amazonaws.com",                 "CreateLogStream"),
    ("logs.amazonaws.com",                 "DescribeLogStreams"),
    ("events.amazonaws.com",               "PutEvents"),
    ("events.amazonaws.com",               "ListRules"),
    ("sns.amazonaws.com",                  "Publish"),
    ("sns.amazonaws.com",                  "ListTopics"),
    ("sqs.amazonaws.com",                  "SendMessage"),
    ("sqs.amazonaws.com",                  "ReceiveMessage"),
    ("sqs.amazonaws.com",                  "GetQueueAttributes"),
    ("dynamodb.amazonaws.com",             "PutItem"),
    ("dynamodb.amazonaws.com",             "Query"),
    ("dynamodb.amazonaws.com",             "UpdateItem"),
    ("dynamodb.amazonaws.com",             "BatchGetItem"),
    ("ecr.amazonaws.com",                  "GetAuthorizationToken"),
    ("ecr.amazonaws.com",                  "BatchGetImage"),
    ("ecs.amazonaws.com",                  "RunTask"),
    ("ecs.amazonaws.com",                  "DescribeTasks"),
    ("sts.amazonaws.com",                  "GetCallerIdentity"),
    ("elasticloadbalancing.amazonaws.com", "DescribeTargetHealth"),
    ("route53.amazonaws.com",              "ChangeResourceRecordSets"),
    ("route53.amazonaws.com",              "ListResourceRecordSets"),
    ("autoscaling.amazonaws.com",          "DescribeAutoScalingGroups"),
    ("apigateway.amazonaws.com",           "GetRestApi"),
    ("cognito-idp.amazonaws.com",          "ListUsers"),
    ("acm.amazonaws.com",                  "DescribeCertificate"),
    ("waf.amazonaws.com",                  "GetWebACL"),
    ("ssm.amazonaws.com",                  "GetParameter"),
    ("ssm.amazonaws.com",                  "DescribeInstanceInformation"),
    ("elasticfilesystem.amazonaws.com",    "DescribeFileSystems"),
    ("rds.amazonaws.com",                  "DescribeDBInstances"),
    ("backup.amazonaws.com",               "ListBackupJobs"),
    ("config.amazonaws.com",               "DescribeConfigRules"),
    ("cloudtrail.amazonaws.com",           "LookupEvents"),
    ("organizations.amazonaws.com",        "ListAccounts"),
    ("guardduty.amazonaws.com",            "GetFindings"),
    ("inspector2.amazonaws.com",           "ListFindings"),
    ("securityhub.amazonaws.com",          "GetFindings"),
    ("access-analyzer.amazonaws.com",      "ListFindings"),
    ("codedeploy.amazonaws.com",           "GetDeployment"),
]


# ===========================================================================
# Persistent principals (anchoring — spec §1)
# ===========================================================================

# Human operators (userName, role_group)
HUMAN_OPERATORS: List[Tuple[str, str]] = [
    ("alice.engineer",  "engineer"),
    ("bob.engineer",    "engineer"),
    ("carol.engineer",  "engineer"),
    ("dave.engineer",   "engineer"),
    ("eve.engineer",    "engineer"),
    ("frank.sre",       "sre"),
    ("gina.sre",        "sre"),
    ("henry.security",  "security"),
]

# CI/CD service accounts and their target deploy roles
CICD_SERVICES = ["github-actions-runner", "circleci-deployer"]
DEPLOY_ROLES = ["deploy-dev", "deploy-staging", "deploy-prod"]
# Weighted target selection: dev common, prod rare
DEPLOY_TARGET_WEIGHTS = {"deploy-dev": 5, "deploy-staging": 3, "deploy-prod": 1}

# Application service roles (assumed by EC2 instance profiles or Lambda)
APP_SERVICE_ROLES = ["app-api-role", "app-worker-role", "app-batch-role"]

# S3 application buckets (§4.4)
APP_BUCKETS = [
    "app-artifacts-prod",
    "app-user-uploads",
    "app-static-assets",
    "app-analytics-events",
]
LOGS_BUCKET = "app-central-logs"


# EC2 instance IDs (persistent — 20 stable app instances)
def build_instance_pool(rng: random.Random, count: int = 20) -> List[str]:
    return ["i-" + "".join(rng.choice("0123456789abcdef") for _ in range(17)) for _ in range(count)]


# IPs — separated by activity type (§4.1)
HOME_IPS = ["203.0.113." + str(i) for i in range(1, 13)]        # dynamic home
OFFICE_IPS = ["198.51.100.10", "198.51.100.20", "198.51.100.30"] # stable office egress
CICD_IPS = ["192.0.2.100", "192.0.2.101", "192.0.2.102"]         # CI/CD egress
VPC_NAT_IPS = ["52.62.100.10", "52.62.100.11"]                    # ap-southeast-2 NAT egress
AWS_INTERNAL_IP = "AWS Internal"


# User agents
SDK_USER_AGENTS = [
    "aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0",
    "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-generic",
    "Boto3/1.34.14 md/Botocore#1.34.14 ua/2.0 os/linux#5.15.0 lang/python#3.11.6",
    "Boto3/1.34.14 md/Botocore#1.34.14 ua/2.0 os/macos#23.4.0 lang/python#3.12.1",
]
CONSOLE_USER_AGENT = "signin.amazonaws.com"
CICD_USER_AGENT = "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0-1051-aws"
APP_SDK_UA = "Boto3/1.34.14 md/Botocore#1.34.14 ua/2.0 os/linux#5.15.0 lang/python#3.11.6 exec-env/AWS_EC2"


# ===========================================================================
# Helpers
# ===========================================================================

def gen_hex(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def gen_request_id(rng: random.Random) -> str:
    h = gen_hex(rng, 32)
    return "{}-{}-{}-{}-{}".format(h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def gen_event_id(rng: random.Random) -> str:
    return gen_request_id(rng)


def gen_principal_id(rng: random.Random, prefix: str = "AIDA") -> str:
    body = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(17))
    return prefix + body


def weighted_pick(rng: random.Random, items_with_weight: List[Tuple[Any, ...]]) -> Tuple[Any, ...]:
    """items_with_weight: list of tuples where the LAST element is the weight."""
    total = sum(t[-1] for t in items_with_weight)
    r = rng.uniform(0, total)
    cum = 0.0
    for t in items_with_weight:
        cum += t[-1]
        if cum >= r:
            return t[:-1]
    return items_with_weight[-1][:-1]


def weighted_pick_dict(rng: random.Random, d: Dict[str, int]) -> str:
    items = list(d.items())
    total = sum(w for _, w in items)
    r = rng.uniform(0, total)
    cum = 0.0
    for k, w in items:
        cum += w
        if cum >= r:
            return k
    return items[-1][0]


# ===========================================================================
# Timestamp sampling (spec §2.3)
# ===========================================================================

def sample_biz_weighted_timestamp(
    rng: random.Random,
    day_start_utc: datetime,
    tz: ZoneInfo,
) -> datetime:
    """60% business hrs / 30% off-hrs (weekdays) / 10% weekends (any hr)."""
    local_start = day_start_utc.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    weekday = local_start.weekday()  # 0=Mon .. 6=Sun

    if weekday >= 5:
        secs = rng.randint(0, 86_399)
    else:
        r = rng.random()
        if r < 0.60:
            secs = 9 * 3600 + rng.randint(0, 32_399)                       # 09:00 - 18:00
        elif r < 0.90:
            off = rng.randint(0, 53_999)                                    # 15 hrs off-hrs
            secs = off if off < 9 * 3600 else 18 * 3600 + (off - 9 * 3600)
        else:
            secs = rng.randint(0, 86_399)

    local_ts = local_start + timedelta(seconds=secs)
    return local_ts.astimezone(timezone.utc)


def sample_uniform_timestamp(rng: random.Random, day_start_utc: datetime) -> datetime:
    return day_start_utc + timedelta(seconds=rng.randint(0, 86_399))


def sample_diurnal_s3_timestamp(
    rng: random.Random,
    day_start_utc: datetime,
    tz: ZoneInfo,
) -> datetime:
    """Sinusoidal — peak at 14:00 local (§2.3)."""
    local_start = day_start_utc.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    while True:
        cand_sec = rng.randint(0, 86_399)
        hr = cand_sec / 3600.0
        weight = 0.5 + 0.5 * math.cos((hr - 14.0) / 24.0 * 2 * math.pi)
        if rng.random() < weight:
            return (local_start + timedelta(seconds=cand_sec)).astimezone(timezone.utc)


def cicd_burst_timestamps_for_day(
    rng: random.Random,
    day_start_utc: datetime,
    tz: ZoneInfo,
    events_per_burst_range: Tuple[int, int] = (200, 500),
) -> List[datetime]:
    """5 bursts on weekdays at 09/11/13/15/17 local, each 5-min long."""
    local_start = day_start_utc.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    if local_start.weekday() >= 5:
        return []

    stamps: List[datetime] = []
    for hour in (9, 11, 13, 15, 17):
        n = rng.randint(*events_per_burst_range)
        for _ in range(n):
            offset_sec = rng.randint(0, 300)
            local_ts = local_start + timedelta(hours=hour, seconds=offset_sec)
            stamps.append(local_ts.astimezone(timezone.utc))
    return stamps


# ===========================================================================
# Identity builders
# ===========================================================================

def make_iam_user_identity(
    user_name: str,
    account_id: str,
    principal_ids: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "type":        "IAMUser",
        "principalId": principal_ids[user_name],
        "arn":         f"arn:aws:iam::{account_id}:user/{user_name}",
        "accountId":   account_id,
        "userName":    user_name,
    }


def make_assumed_role_identity(
    role_name: str,
    session_name: str,
    account_id: str,
    principal_ids: Dict[str, str],
    creation_date: datetime,
) -> Dict[str, Any]:
    role_pid = principal_ids[role_name]
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


# ===========================================================================
# Event constructor
# ===========================================================================

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
    category: str,
    seed: int,
    request_parameters: Optional[Dict[str, Any]] = None,
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
        "requestID":          gen_request_id(rng),
        "eventID":            gen_event_id(rng),
        "eventType":          "AwsApiCall",
        "recipientAccountId": account_id,
        "pathtriage": {
            "corpus_version": corpus_version,
            "category":       category,
            "generator_seed": seed,
        },
    }


# ===========================================================================
# Category-specific event builders
# ===========================================================================

def build_read_heavy_event(
    rng: random.Random,
    ts: datetime,
    account_id: str,
    principal_ids: Dict[str, str],
    corpus_version: str,
    seed: int,
) -> Dict[str, Any]:
    """§4.1 — human operator, console/CLI, IP mix home+office."""
    event_name, event_source = weighted_pick(rng, READ_HEAVY_ACTIONS)
    user_name, _ = rng.choice(HUMAN_OPERATORS)

    # 60% console (office-favored), 40% CLI
    if rng.random() < 0.6:
        ua = CONSOLE_USER_AGENT
        source_ip = rng.choice(OFFICE_IPS) if rng.random() < 0.7 else rng.choice(HOME_IPS)
    else:
        ua = rng.choice(SDK_USER_AGENTS)
        source_ip = rng.choice(HOME_IPS) if rng.random() < 0.6 else rng.choice(OFFICE_IPS)

    ident = make_iam_user_identity(user_name, account_id, principal_ids)
    return make_event(
        rng, ts, event_source, event_name, ident, source_ip, ua,
        account_id, corpus_version, "read_heavy_browse", seed,
    )


def build_cicd_burst_event(
    rng: random.Random,
    ts: datetime,
    account_id: str,
    principal_ids: Dict[str, str],
    corpus_version: str,
    seed: int,
    # Burst-shared context so events in a burst chain cohere
    burst_ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """§4.2 — CI/CD service assumes deploy role then emits deploy events."""
    if burst_ctx is None or "role" not in burst_ctx:
        target_role = weighted_pick_dict(rng, DEPLOY_TARGET_WEIGHTS)
        service = rng.choice(CICD_SERVICES)
        session = f"{service}-{gen_hex(rng, 8)}"
        source_ip = rng.choice(CICD_IPS)
    else:
        target_role = burst_ctx["role"]
        service = burst_ctx["service"]
        session = burst_ctx["session"]
        source_ip = burst_ctx["source_ip"]

    event_source, event_name = rng.choice(CICD_DEPLOY_STEPS)

    ident = make_assumed_role_identity(
        target_role, session, account_id, principal_ids,
        creation_date=ts - timedelta(seconds=rng.randint(30, 600)),
    )

    req_params: Dict[str, Any] = {}
    if event_name == "PutObject":
        req_params = {"bucketName": "app-artifacts-prod", "key": f"deploy/{gen_hex(rng, 8)}.zip"}
    elif event_name in ("CreateChangeSet", "ExecuteChangeSet", "DescribeStacks", "DescribeStackEvents"):
        req_params = {"stackName": f"app-{target_role.replace('deploy-', '')}"}
    elif event_name == "UpdateFunctionCode":
        req_params = {"functionName": f"app-handler-{target_role.replace('deploy-', '')}"}
    elif event_name == "AssumeRole":
        req_params = {
            "roleArn": f"arn:aws:iam::{account_id}:role/{target_role}",
            "roleSessionName": session,
        }

    return make_event(
        rng, ts, event_source, event_name, ident, source_ip, CICD_USER_AGENT,
        account_id, corpus_version, "cicd_role_assumption", seed,
        request_parameters=req_params,
    )


def build_s3_access_event(
    rng: random.Random,
    ts: datetime,
    account_id: str,
    principal_ids: Dict[str, str],
    instance_pool: List[str],
    corpus_version: str,
    seed: int,
) -> Dict[str, Any]:
    """§4.4 — application service role, GetObject/PutObject."""
    event_name = "GetObject" if rng.random() < 0.7 else "PutObject"
    role = rng.choice(APP_SERVICE_ROLES)
    instance = rng.choice(instance_pool)
    session = instance  # instance-profile session name

    ident = make_assumed_role_identity(
        role, session, account_id, principal_ids,
        creation_date=ts - timedelta(seconds=rng.randint(60, 3600)),
    )

    bucket = rng.choice(APP_BUCKETS)
    key = f"data/{gen_hex(rng, 4)}/{gen_hex(rng, 8)}.json"

    source_ip = rng.choice(VPC_NAT_IPS)

    return make_event(
        rng, ts, "s3.amazonaws.com", event_name, ident, source_ip, APP_SDK_UA,
        account_id, corpus_version, "s3_access", seed,
        request_parameters={"bucketName": bucket, "key": key},
    )


def build_devops_iam_write_event(
    rng: random.Random,
    ts: datetime,
    event_name: str,
    account_id: str,
    principal_ids: Dict[str, str],
    corpus_version: str,
    seed: int,
) -> Dict[str, Any]:
    """§4.3 — FP-critical IAM writes from human SREs/security ops."""
    # Restrict to sre/security personas — realistic ops attribution
    ops_pool = [u for u in HUMAN_OPERATORS if u[1] in ("sre", "security")]
    user_name, _ = rng.choice(ops_pool)
    ident = make_iam_user_identity(user_name, account_id, principal_ids)

    # Ops writes come from office egress dominantly
    source_ip = rng.choice(OFFICE_IPS) if rng.random() < 0.8 else rng.choice(HOME_IPS)
    ua = rng.choice(SDK_USER_AGENTS)

    req_params: Dict[str, Any] = {}
    if event_name == "CreateRole":
        req_params = {
            "roleName": f"svc-{gen_hex(rng, 4)}-role",
            "assumeRolePolicyDocument": (
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
            ),
        }
    elif event_name == "AttachRolePolicy":
        managed = rng.choice([
            "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "arn:aws:iam::aws:policy/AmazonSESFullAccess",
            "arn:aws:iam::aws:policy/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess",
        ])
        req_params = {"roleName": f"svc-{gen_hex(rng, 4)}-role", "policyArn": managed}
    elif event_name == "PutRolePolicy":
        req_params = {
            "roleName":       f"svc-{gen_hex(rng, 4)}-role",
            "policyName":     f"inline-{gen_hex(rng, 4)}",
            "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}',
        }
    elif event_name == "CreatePolicyVersion":
        # The single sharpest FP signal for primitive 03 — realistic customer-managed policy update
        req_params = {
            "policyArn":    f"arn:aws:iam::{account_id}:policy/CustomAppAccess-{gen_hex(rng, 4)}",
            "policyDocument": (
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],'
                '"Resource":"arn:aws:s3:::app-user-uploads/*"}]}'
            ),
            "setAsDefault": True,
        }

    return make_event(
        rng, ts, "iam.amazonaws.com", event_name, ident, source_ip, ua,
        account_id, corpus_version, "devops_iam", seed,
        request_parameters=req_params,
    )


def build_devops_iam_read_event(
    rng: random.Random,
    ts: datetime,
    account_id: str,
    principal_ids: Dict[str, str],
    corpus_version: str,
    seed: int,
) -> Dict[str, Any]:
    event_source, event_name = rng.choice(DEVOPS_IAM_READS)
    user_name, _ = rng.choice(HUMAN_OPERATORS)
    ident = make_iam_user_identity(user_name, account_id, principal_ids)

    source_ip = rng.choice(OFFICE_IPS) if rng.random() < 0.6 else rng.choice(HOME_IPS)
    ua = CONSOLE_USER_AGENT if rng.random() < 0.5 else rng.choice(SDK_USER_AGENTS)

    return make_event(
        rng, ts, event_source, event_name, ident, source_ip, ua,
        account_id, corpus_version, "devops_iam", seed,
    )


def build_ec2_lifecycle_write_event(
    rng: random.Random,
    ts: datetime,
    event_name: str,
    account_id: str,
    principal_ids: Dict[str, str],
    instance_pool: List[str],
    corpus_version: str,
    seed: int,
) -> Dict[str, Any]:
    """§4.5 — RunInstances / TerminateInstances / AttachInstanceProfile."""
    # From CI/CD deploy identity — realistic
    target_role = weighted_pick_dict(rng, DEPLOY_TARGET_WEIGHTS)
    session = f"github-actions-runner-{gen_hex(rng, 8)}"
    ident = make_assumed_role_identity(
        target_role, session, account_id, principal_ids,
        creation_date=ts - timedelta(seconds=rng.randint(30, 600)),
    )

    req_params: Dict[str, Any] = {}
    if event_name == "RunInstances":
        req_params = {
            "instanceType":   rng.choice(["t3.micro", "t3.small", "t3.medium"]),
            "imageId":        "ami-" + gen_hex(rng, 17),
            "minCount":       1,
            "maxCount":       1,
        }
    elif event_name == "TerminateInstances":
        req_params = {"instancesSet": {"items": [{"instanceId": rng.choice(instance_pool)}]}}
    elif event_name == "AttachInstanceProfile":
        req_params = {
            "instanceId":      rng.choice(instance_pool),
            "iamInstanceProfile": {"name": rng.choice(APP_SERVICE_ROLES) + "-profile"},
        }

    return make_event(
        rng, ts, "ec2.amazonaws.com", event_name, ident,
        rng.choice(CICD_IPS), CICD_USER_AGENT,
        account_id, corpus_version, "ec2_lifecycle", seed,
        request_parameters=req_params,
    )


def build_ec2_lifecycle_misc_event(
    rng: random.Random,
    ts: datetime,
    account_id: str,
    principal_ids: Dict[str, str],
    corpus_version: str,
    seed: int,
) -> Dict[str, Any]:
    event_source, event_name = rng.choice(EC2_LIFECYCLE_MISC)
    user_name, _ = rng.choice(HUMAN_OPERATORS)
    ident = make_iam_user_identity(user_name, account_id, principal_ids)

    source_ip = rng.choice(OFFICE_IPS) if rng.random() < 0.5 else rng.choice(HOME_IPS)
    ua = CONSOLE_USER_AGENT if rng.random() < 0.5 else rng.choice(SDK_USER_AGENTS)

    return make_event(
        rng, ts, event_source, event_name, ident, source_ip, ua,
        account_id, corpus_version, "ec2_lifecycle", seed,
    )


def build_long_tail_event(
    rng: random.Random,
    ts: datetime,
    account_id: str,
    principal_ids: Dict[str, str],
    instance_pool: List[str],
    corpus_version: str,
    seed: int,
) -> Dict[str, Any]:
    """§4.6 — uniform across ~50 low-frequency actions."""
    event_source, event_name = rng.choice(LONG_TAIL_ACTIONS)

    # Half from app service roles (application-tier calls), half from humans
    if rng.random() < 0.5:
        role = rng.choice(APP_SERVICE_ROLES)
        session = rng.choice(instance_pool)
        ident = make_assumed_role_identity(
            role, session, account_id, principal_ids,
            creation_date=ts - timedelta(seconds=rng.randint(60, 3600)),
        )
        source_ip = rng.choice(VPC_NAT_IPS)
        ua = APP_SDK_UA
    else:
        user_name, _ = rng.choice(HUMAN_OPERATORS)
        ident = make_iam_user_identity(user_name, account_id, principal_ids)
        source_ip = rng.choice(OFFICE_IPS + HOME_IPS)
        ua = rng.choice(SDK_USER_AGENTS)

    return make_event(
        rng, ts, event_source, event_name, ident, source_ip, ua,
        account_id, corpus_version, "long_tail", seed,
    )


# ===========================================================================
# Main generation loop
# ===========================================================================

def build_principal_id_map(rng: random.Random) -> Dict[str, str]:
    """Persistent principalId assignment for anchoring."""
    pids: Dict[str, str] = {}
    for user_name, _ in HUMAN_OPERATORS:
        pids[user_name] = gen_principal_id(rng, "AIDA")
    for role in DEPLOY_ROLES + APP_SERVICE_ROLES:
        pids[role] = gen_principal_id(rng, "AROA")
    return pids


def compute_daily_budgets(rate: int) -> Dict[str, int]:
    return {cat: int(round(rate * share)) for cat, share in CATEGORY_SHARES.items()}


def generate_corpus(
    rate: int,
    days: int,
    seed: int,
    account_id: str,
    timezone_name: str,
    corpus_version: str,
    output_path: Path,
    start_date: datetime,
) -> Tuple[int, str]:
    """
    Returns (event_count, sha256_hex).
    """
    rng = random.Random(seed)
    tz = ZoneInfo(timezone_name)

    principal_ids = build_principal_id_map(rng)
    instance_pool = build_instance_pool(rng, count=20)
    daily_budgets = compute_daily_budgets(rate)

    total_events = 0
    hasher = hashlib.sha256()

    with open(output_path, "wb") as fh:
        for day_idx in range(days):
            day_start_utc = start_date + timedelta(days=day_idx)
            day_events: List[Dict[str, Any]] = []

            # -----------------------------------------------------------------
            # 1. Read-heavy browsing (§4.1) — biz-hours weighted
            # -----------------------------------------------------------------
            for _ in range(daily_budgets["read_heavy_browse"]):
                ts = sample_biz_weighted_timestamp(rng, day_start_utc, tz)
                day_events.append(
                    build_read_heavy_event(rng, ts, account_id, principal_ids, corpus_version, seed)
                )

            # -----------------------------------------------------------------
            # 2. CI/CD role assumptions (§4.2)
            #    Split between: (a) burst events during biz hours, and
            #                   (b) diffuse remainder biz-hours weighted
            # -----------------------------------------------------------------
            burst_stamps = cicd_burst_timestamps_for_day(rng, day_start_utc, tz)
            budget_cicd = daily_budgets["cicd_role_assumption"]
            burst_used = min(len(burst_stamps), budget_cicd)
            burst_stamps = burst_stamps[:burst_used]

            # Group burst timestamps into ~5 burst contexts per weekday
            # (each burst has a coherent role/session)
            if burst_stamps:
                # Rebuild contexts by hour clustering
                by_hour: Dict[int, List[datetime]] = {}
                for ts in burst_stamps:
                    hr = ts.astimezone(tz).hour
                    by_hour.setdefault(hr, []).append(ts)
                for hr, stamps_in_burst in by_hour.items():
                    ctx = {
                        "role":      weighted_pick_dict(rng, DEPLOY_TARGET_WEIGHTS),
                        "service":   rng.choice(CICD_SERVICES),
                        "session":   f"gha-{gen_hex(rng, 8)}",
                        "source_ip": rng.choice(CICD_IPS),
                    }
                    for ts in stamps_in_burst:
                        day_events.append(
                            build_cicd_burst_event(rng, ts, account_id, principal_ids, corpus_version, seed, ctx)
                        )

            # Diffuse remainder
            diffuse_cicd = budget_cicd - burst_used
            for _ in range(diffuse_cicd):
                ts = sample_biz_weighted_timestamp(rng, day_start_utc, tz)
                day_events.append(
                    build_cicd_burst_event(rng, ts, account_id, principal_ids, corpus_version, seed, None)
                )

            # -----------------------------------------------------------------
            # 3. S3 access (§4.4) — diurnal peak at 14:00 local
            # -----------------------------------------------------------------
            for _ in range(daily_budgets["s3_access"]):
                ts = sample_diurnal_s3_timestamp(rng, day_start_utc, tz)
                day_events.append(
                    build_s3_access_event(rng, ts, account_id, principal_ids, instance_pool, corpus_version, seed)
                )

            # -----------------------------------------------------------------
            # 4. DevOps IAM (§4.3) — fixed writes + read-only fill
            # -----------------------------------------------------------------
            budget_iam = daily_budgets["devops_iam"]
            iam_writes_this_day = 0
            for event_name, event_source, per_day_rate in DEVOPS_IAM_WRITES:
                for _ in range(per_day_rate):
                    ts = sample_biz_weighted_timestamp(rng, day_start_utc, tz)
                    day_events.append(
                        build_devops_iam_write_event(
                            rng, ts, event_name, account_id, principal_ids, corpus_version, seed,
                        )
                    )
                    iam_writes_this_day += 1

            iam_reads_this_day = max(budget_iam - iam_writes_this_day, 0)
            for _ in range(iam_reads_this_day):
                ts = sample_biz_weighted_timestamp(rng, day_start_utc, tz)
                day_events.append(
                    build_devops_iam_read_event(rng, ts, account_id, principal_ids, corpus_version, seed)
                )

            # -----------------------------------------------------------------
            # 5. EC2 lifecycle (§4.5) — fixed writes + misc fill
            # -----------------------------------------------------------------
            budget_ec2 = daily_budgets["ec2_lifecycle"]
            ec2_writes_this_day = 0
            for event_name, event_source, per_day_rate in EC2_LIFECYCLE_WRITES:
                for _ in range(per_day_rate):
                    ts = sample_biz_weighted_timestamp(rng, day_start_utc, tz)
                    day_events.append(
                        build_ec2_lifecycle_write_event(
                            rng, ts, event_name, account_id, principal_ids, instance_pool,
                            corpus_version, seed,
                        )
                    )
                    ec2_writes_this_day += 1

            ec2_misc_this_day = max(budget_ec2 - ec2_writes_this_day, 0)
            for _ in range(ec2_misc_this_day):
                ts = sample_biz_weighted_timestamp(rng, day_start_utc, tz)
                day_events.append(
                    build_ec2_lifecycle_misc_event(rng, ts, account_id, principal_ids, corpus_version, seed)
                )

            # -----------------------------------------------------------------
            # 6. Long-tail (§4.6)
            # -----------------------------------------------------------------
            for _ in range(daily_budgets["long_tail"]):
                ts = sample_uniform_timestamp(rng, day_start_utc)
                day_events.append(
                    build_long_tail_event(rng, ts, account_id, principal_ids, instance_pool, corpus_version, seed)
                )

            # -----------------------------------------------------------------
            # Sort within-day by eventTime, then write
            # -----------------------------------------------------------------
            day_events.sort(key=lambda e: e["eventTime"])
            for evt in day_events:
                line = (json.dumps(evt, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
                fh.write(line)
                hasher.update(line)
                total_events += 1

            print(
                f"  day {day_idx+1}/{days} ({day_start_utc.date()}): "
                f"{len(day_events):,} events",
                file=sys.stderr,
            )

    return total_events, hasher.hexdigest()


# ===========================================================================
# CLI
# ===========================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate synthetic CloudTrail baseline corpus for PathTriage evaluation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--rate",       type=int, default=100_000,
                   help="Events per day (default: 100000).")
    p.add_argument("--days",       type=int, default=7,
                   help="Corpus duration in days (default: 7).")
    p.add_argument("--seed",       type=int,
                   default=int(os.environ.get("PATHTRIAGE_BASELINE_SEED", 42)),
                   help="RNG seed (env: PATHTRIAGE_BASELINE_SEED, default: 42).")
    p.add_argument("--timezone",   type=str, default="Australia/Sydney",
                   help="Timezone for business-hours weighting.")
    p.add_argument("--account-id", type=str, default="000000000000",
                   help="AWS account ID for userIdentity/recipientAccountId.")
    p.add_argument("--output",     type=Path, default=Path("baseline_corpus.jsonl"),
                   help="Output JSONL path.")
    p.add_argument("--version",    type=str, default=None,
                   help="Corpus version tag (default: YYYY-MM-DD-1).")
    p.add_argument("--start-date", type=str, default=None,
                   help="Corpus start date UTC (ISO, default: 7 days ago at 00:00Z).")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    corpus_version = args.version or (datetime.now(timezone.utc).strftime("%Y-%m-%d") + "-1")
    if args.start_date:
        start_date = datetime.fromisoformat(args.start_date).replace(tzinfo=timezone.utc)
    else:
        today_utc = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = today_utc - timedelta(days=args.days)

    print("=" * 72, file=sys.stderr)
    print("PathTriage baseline corpus generation", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print(f"  rate          : {args.rate:,} events/day", file=sys.stderr)
    print(f"  days          : {args.days}", file=sys.stderr)
    print(f"  seed          : {args.seed}", file=sys.stderr)
    print(f"  timezone      : {args.timezone}", file=sys.stderr)
    print(f"  account-id    : {args.account_id}", file=sys.stderr)
    print(f"  start_date    : {start_date.isoformat()}", file=sys.stderr)
    print(f"  version       : {corpus_version}", file=sys.stderr)
    print(f"  output        : {args.output}", file=sys.stderr)
    print(f"  category mix  : {CATEGORY_SHARES}", file=sys.stderr)
    print("-" * 72, file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)

    count, corpus_hash = generate_corpus(
        rate=args.rate,
        days=args.days,
        seed=args.seed,
        account_id=args.account_id,
        timezone_name=args.timezone,
        corpus_version=corpus_version,
        output_path=args.output,
        start_date=start_date,
    )

    file_size_mb = args.output.stat().st_size / (1024 * 1024)

    print("-" * 72, file=sys.stderr)
    print(f"  events written: {count:,}", file=sys.stderr)
    print(f"  file size     : {file_size_mb:.1f} MB", file=sys.stderr)
    print(f"  sha256        : {corpus_hash}", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print(f"  → record this hash in evaluation_report.md as the corpus fingerprint",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
