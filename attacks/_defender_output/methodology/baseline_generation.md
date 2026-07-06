# Synthetic Benign CloudTrail Corpus — Generator Specification

## Purpose

The evaluation protocol (`evaluation_protocol.md`) requires a benign CloudTrail corpus against which each detection primitive is measured for false-positive rate. This document specifies the generator that produces that corpus.

The generator is a Python script (`methodology/generate_baseline.py`, produced during Phase 1 build) that emits CloudTrail Lake-format JSON events at a configurable rate, with realistic event mixes for a small-to-medium enterprise.

## 1. Design goals

- **Reproducibility**: same seed → same corpus byte-for-byte.
- **Realism (bounded)**: event names, response codes, `userIdentity` structure, and resource ARNs conform to CloudTrail schema. Category mixes reference public CloudTrail volume studies (§2.1). Realism is bounded by synthetic origin — see `evaluation_protocol.md` §5.1.
- **Configurability**: event rate, duration, category mix are all parameters, so the same generator serves the reference measurement (100k/day) and the sensitivity analysis at 10k/day and 1M/day.
- **Anchoring**: principal identities, resource ARNs, and IP addresses persist across the corpus. Baseline-join queries in the primitives need historical anchors to work; a corpus of purely one-off principals defeats the baseline-anomaly detection design.

## 2. Event-mix approximation

### 2.1 Small-to-medium enterprise reference (~100k events/day)

The reference rate of 100k events/day is drawn from three sources:

1. **AWS's own CloudTrail volume references**: the CloudTrail pricing page cites 100,000 management events/month as included in the free tier; enterprises 10× that ratio (single account, moderate activity) sit around 100k/day. Larger enterprises with 100+ accounts scale linearly.
2. **Duo Labs public CloudTrail dataset** (github.com/duo-labs/cloudtrail-partitioner sample corpus): 3M events across 30 days = ~100k/day for a mid-sized SaaS.
3. **Author's own AWS account** during PathTriage build (Feb–Jul 2026): 8–15k events/day. Extrapolated to a small enterprise with three engineers, three environments (dev/staging/prod), and moderate CI/CD activity, ~50–100k/day is plausible.

The 100k/day rate is therefore representative of a small enterprise, a mid-sized team within a larger enterprise, or a single-tenant SaaS. Sensitivity analysis at 10k/day (individual developer) and 1M/day (large enterprise, ~10 concurrent teams) bounds the reference.

### 2.2 Category distribution

Categories and their share of the 100k/day corpus:

| Category | % of events | Rationale |
|---|---|---|
| Read-heavy console browsing | 40% | `Describe*`, `List*`, `Get*` from human operators using the console. Highest-volume category in most enterprises. |
| CI/CD role assumptions | 25% | Repeated `sts:AssumeRole` from CI/CD service to deployment roles, followed by short bursts of `CloudFormation`, `S3:PutObject`, etc. |
| S3 access patterns | 15% | Application-level `s3:GetObject` / `PutObject` at high frequency to a small set of buckets. |
| Dev-ops IAM changes | 8% | Legitimate `iam:CreateRole`, `AttachPolicy`, `PutRolePolicy` during setup/tear-down. These are the most detection-relevant benign events; they must be realistic. |
| EC2 lifecycle events | 7% | `RunInstances`, `TerminateInstances`, `AttachInstanceProfile` in bursty CI/CD patterns. |
| Long-tail low-frequency | 5% | KMS, Secrets Manager, Lambda invocations, CloudWatch operations, etc. Uniform-random distribution over ~50 service actions. |

### 2.3 Temporal patterns

Events are not uniformly distributed. The generator applies:

- **Business-hours weighting**: 60% of events between 09:00–18:00 in a configurable timezone (default Australia/Sydney), 30% off-hours, 10% weekends.
- **CI/CD bursts**: every 2 hours during business hours, a 5-minute burst of 200–500 events representing a deploy pipeline.
- **Diurnal S3 pattern**: application S3 accesses follow a sinusoidal pattern with peak at 14:00 local.

Business-hours weighting matters for primitives that use time-of-day as an anomaly signal (none in the current five primitives, but reserved for extension).

## 3. Generator implementation

### 3.1 Input parameters

```
--rate           events per day (default: 100000)
--days           corpus duration (default: 7)
--seed           RNG seed (default: 42; env: PATHTRIAGE_BASELINE_SEED)
--timezone       for business-hours weighting (default: Australia/Sydney)
--account-id     AWS account ID for event userIdentity (default: 000000000000)
--output         output path (default: baseline_corpus.jsonl)
--version        corpus version tag written into every event
                 (default: YYYY-MM-DD-N where N is the run number this day)
```

### 3.2 Output schema (CloudTrail Lake JSON)

Each line of the output file is one CloudTrail event. Schema fields:

```json
{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "IAMUser" | "AssumedRole" | "Root" | "AWSService",
    "principalId": "AIDAI...",
    "arn": "arn:aws:iam::000000000000:user/...",
    "accountId": "000000000000",
    "userName": "..."
  },
  "eventTime": "2026-06-15T09:23:14Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "DescribeInstances",
  "awsRegion": "ap-southeast-2",
  "sourceIPAddress": "203.0.113.42",
  "userAgent": "aws-cli/2.15.0",
  "requestParameters": {...},
  "responseElements": null,
  "requestID": "...",
  "eventID": "...",
  "eventType": "AwsApiCall",
  "recipientAccountId": "000000000000",
  "pathtriage": {
    "corpus_version": "2026-07-04-1",
    "category": "read_heavy_browse",
    "generator_seed": 42
  }
}
```

The `pathtriage` field is metadata for evaluation scoring; it is stripped when the corpus is loaded into CloudTrail Lake (CTL doesn't accept unknown top-level fields), but retained in the labelled shadow copy used for TP/FP classification.

### 3.3 Seed control and reproducibility

The generator uses `random.Random(seed)` — no dependency on the system RNG. All timestamp offsets, category selections, principal choices, and resource ARN generations are drawn from this single stream. Running with the same seed and parameters produces the same corpus byte-for-byte.

Verification: the Phase 4 evaluation includes a smoke test that hashes the output file after generation and asserts it matches a recorded hash for the reference corpus (seed=42, rate=100000, days=7).

## 4. Categories — detailed specification

### 4.1 Read-heavy console browsing

Actions drawn from a weighted set: `DescribeInstances` (25%), `ListBuckets` (15%), `ListRoles` (12%), `GetPolicy` (10%), `DescribeLoadBalancers` (8%), `ListFunctions` (7%), and 20+ others at diminishing weight.

`userIdentity.type` = `IAMUser` or `AssumedRole` from a fixed pool of 8 human operators (5 engineers, 2 SREs, 1 security). Source IP drawn from a pool of 12 addresses representing home internet (dynamic) and 3 office egress IPs (stable).

### 4.2 CI/CD role assumptions

Pattern: `sts:AssumeRole` from CI/CD service principal to one of {deploy-dev, deploy-staging, deploy-prod} roles, followed by 20–80 events representing a deploy: `CloudFormation:CreateStack` or `UpdateStack`, `S3:PutObject` (artifact upload), `Lambda:UpdateFunctionCode`, etc.

Bursts occur at 2-hour intervals during business hours. Deploys to prod are ~2x rarer than to dev.

### 4.3 Dev-ops IAM changes

This category needs the highest realism because IAM-modification primitives (02, 03) can misfire on benign IAM changes. Actions:

- `iam:CreateRole` — new microservice setup, ~2 per day
- `iam:AttachRolePolicy` — attaching AWS-managed policies (SES, S3ReadOnly) to newly-created service roles, ~5 per day
- `iam:PutRolePolicy` — inline policies for scoped access, ~3 per day
- `iam:CreatePolicyVersion` — routine version update for a customer-managed policy, ~1 per day

The last item — `CreatePolicyVersion` in benign traffic — is the sharpest FP challenge for primitive 03 (IAM modification — mutate). The generator produces it at 1/day rate to stress-test.

### 4.4 S3 access patterns

Application `GetObject` / `PutObject` at 5,000/day, distributed across a fixed pool of 4 application buckets and 1 logs bucket. `userIdentity.type` = `AssumedRole` from an application service role.

### 4.5 EC2 lifecycle events

`RunInstances` and `TerminateInstances` in bursts around CI/CD deploys (integration test environments). ~150 lifecycle events/day.

Importantly for primitive 01 (IMDS extraction), the generator includes benign `AssumeRole` events from EC2 instance profiles — these are what a legitimate application does when it needs credentials for a downstream call. These should not fire primitive 01; the primitive's baseline-join condition (unexpected source IP for the instance's role) is what discriminates.

### 4.6 Long-tail low-frequency actions

5% of events distributed uniformly over ~50 actions across KMS, Secrets Manager, Lambda, CloudWatch, EventBridge, SNS, SQS, DynamoDB. This category smokes out primitives that over-fire on unusual-but-legitimate service actions.

## 5. Corpus versioning

Each corpus is tagged `PATHTRIAGE_CORPUS_V=YYYY-MM-DD-N` where N increments if the corpus is regenerated the same day (e.g., after a generator fix).

The reference corpus for the primary evaluation is `2026-07-XX-1` (X to be filled in on Phase 4 execution). Its hash is recorded in `evaluation_report.md`. All primitive evaluations cite the corpus version.
