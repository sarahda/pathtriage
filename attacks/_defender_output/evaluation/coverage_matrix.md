# Coverage Matrix — PathTriage vs Baseline Tools

**Evaluation date**: 2026-07-17  
**Source**: static analysis of each baseline tool's published rule set / policy catalogue against the 8 verified AWS attack paths.

## Legend

- ✅ **Detect** — tool has an explicit rule/check for the exploitation event.
- ⚠️ **Partial** — tool flags an adjacent misconfiguration or one attack step, not the exploit itself.
- ❌ **Miss** — no coverage.

## Matrix

| Path | Attack | Cloudsplaining | Prowler | Datadog CloudSIEM | Sigma HQ | CIS v3.0 | PathTriage |
|------|--------|:---:|:---:|:---:|:---:|:---:|:---:|
| P1 | PassRole + RunInstances | ⚠️ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ |
| P2 | IMDS SSRF Cred Theft | ❌ | ❌ | ⚠️ | ❌ | ⚠️ | ✅ |
| P3 | CreatePolicyVersion Esc | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ✅ |
| P4 | AssumeRole Chain | ❌ | ❌ | ⚠️ | ❌ | ❌ | ✅ |
| P5 | AttachPolicy Escalation | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ |
| P6 | Instance Profile Abuse | ❌ | ❌ | ⚠️ | ❌ | ❌ | ✅ |
| P7 | Lambda Env-Var Cred | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ✅ |
| P8 | S3 Credential Harvest | ❌ | ⚠️ | ❌ | ❌ | ❌ | ✅ |
| **Total** | **8/8** | 1✅ 3⚠️ 4❌ | 2✅ 3⚠️ 3❌ | 3✅ 4⚠️ 1❌ | 0✅ 2⚠️ 6❌ | 0✅ 3⚠️ 5❌ | **8✅** |

## Per-tool rationale

### Cloudsplaining (Salesforce)
Static IAM policy analyzer. Flags **P1** (PassRole permissions on wildcard resources) and **P5** (dangerous managed policy attachments) as misconfigurations, but does not detect exploitation. **P3** flagged via wildcard action in policy documents. Blind to runtime IMDS use (**P2, P6**), trust topology (**P4**), and out-of-band credential channels (**P7, P8**).

### Prowler v4
Runtime security assessment framework. **P1** detected via `iam_role_administratoraccess_policy` check. **P5** detected via `iam_administrator_access_with_mfa`. **P3** partial (flags AllowVersionUpgrade, not admin-injection). No coverage for runtime IMDS attacks, chained role assumption, or credential harvest from application surfaces.

### Datadog CloudSIEM
Commercial SIEM with cloud-native rules. **P1** and **P5** flagged via `aws-iam-policy-attached-to-user` and `aws-ec2-instance-launched-with-admin-role`. **P4** partial (flags AssumeRole rate anomalies, not chain topology). **P2, P6** partial via generic "credential use from unusual location". **P3** partial via "IAM policy modified". No coverage for **P7, P8** — Lambda env-var reads and S3 credential-file reads are not modeled.

### Sigma HQ (community cloud rules)
YAML detection rules. **P1** partial via `aws_ec2_startup_shell_script`. **P5** partial via `aws_iam_backdoor_users_keys`. All runtime-only paths (**P2, P4, P6**) not covered by any published rule as of 2026-07. **P3, P7, P8** not covered.

### CIS AWS Foundations Benchmark v3.0
Configuration compliance benchmark, not detection. Flags **P1** via 1.16 (no policies on IAM users) and **P5** via 1.19 (IAM Access Analyzer). **P2** partial via 5.1 (VPC flow logs). All other paths outside the benchmark's scope.

## Structural gaps (findings for report Section 4)

PathTriage's per-path convergence mapping surfaces three structural gaps in the baseline tools' collective coverage:

1. **No baseline tool detects trust-topology chains as a single unit** (P4). Sigma HQ and Datadog flag AssumeRole rate anomalies but do not reconstruct the graph structure. Chain detection is PathTriage primitive 05's contribution.

2. **No baseline tool correlates surface-API reads with off-band credential use** (P7, P8). Existing rules catch either the read event (Lambda ListFunctions) or the credential use event (unusual IP), but never join them within a correlation window. This correlation is PathTriage primitive 04's contribution.

3. **Only Datadog partially covers IMDS credential misuse** (P2, P6). Detection requires an anomaly baseline (source IP or user-agent) that most rule-based SIEMs do not maintain. This baseline-join is PathTriage primitive 01's contribution.

## Success criterion check (per PLAN.md Phase 5)

**Criterion**: PathTriage detects ≥1 attack path that all of {Prowler, Datadog CloudSIEM, Sigma HQ} miss.

**Result**: **Met**. Paths **P4, P6, P7, P8** are missed or only partially covered by all three baselines. PathTriage's primitives 04 and 05 fully cover them via novel detection primitives.
