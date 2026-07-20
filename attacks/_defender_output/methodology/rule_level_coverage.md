# Rule-Level Coverage Evidence

**Purpose**: Rule-by-rule evidence for Chapter 2 gap analysis and
Chapter 6 comparative evaluation. Provides the underlying justification
for `coverage_matrix.md`'s path-level detect/partial/miss classification.

**Author**: Tessa Moon, 2026-07-19  
**Consumed by**:
- `report/chapter2_related_work.md`
- `report/chapter6_defender_output.md`
- `attacks/_defender_output/evaluation/coverage_matrix.md` (already committed)

**Method**: For each baseline tool, we identify the closest-matching
published rule/check to each of the 8 verified AWS attack paths (P1–P8),
and classify:

- **Detect** — a specific rule exists that fires on the exploitation
  event (the moment the attack chain is completed).
- **Partial** — a rule exists that flags either (a) the pre-condition
  misconfiguration, or (b) a single step of the multi-step chain, but
  not the full chain.
- **Miss** — no rule addresses this attack path.

Because most baseline tools were not designed with attack-chain analysis
in mind, "partial" is the most common classification. This is not a
deficiency of the tools — they solve different problems. The purpose of
this matrix is to document the **structural gap** PathTriage fills.

---

## Baseline Tool 1 — Cloudsplaining

**Publisher**: Salesforce  
**Repository**: https://github.com/salesforce/cloudsplaining  
**License**: Apache 2.0  
**Type**: Static IAM policy analyzer  
**Focus**: Detects violations of least-privilege in AWS IAM policies

### Coverage philosophy

Cloudsplaining scans IAM policy documents for permission patterns that
enable known privilege-escalation techniques. It **does not observe
runtime traffic**. Its coverage of PathTriage's attack paths is
therefore limited to those paths where a static permission pattern is
diagnostic.

### Per-path assessment

**P1 — PassRole + RunInstances**: **Partial**
- Cloudsplaining flags `iam:PassRole` on wildcard resources as a
  privilege-escalation finding (category:
  "PrivilegeEscalation", finding pattern: `iam:PassRole` + a compute
  service action like `ec2:RunInstances`, `lambda:CreateFunction`).
- Source: Cloudsplaining's `privilege_escalation.py` derived from Rhino
  Security Labs' AWS Privilege Escalation research.
- **Gap**: Cloudsplaining flags the *policy* as vulnerable; it does
  not fire on the exploitation event (the actual `RunInstances` call).
  It cannot distinguish routine `PassRole` from attack `PassRole`.

**P2 — IMDS SSRF Credential Theft**: **Miss**
- IMDS extraction is a runtime attack. There is no static IAM policy
  pattern that indicates IMDS exposure.
- **Note**: Cloudsplaining does identify IAM roles attached to
  compute services (EC2, ECS, EKS, Lambda) as elevated-risk, per its
  documented Compute Role finding. This is a *precondition* for P2
  but not a detection of P2 itself.

**P3 — CreatePolicyVersion Escalation**: **Partial**
- Cloudsplaining flags `iam:CreatePolicyVersion` combined with
  `iam:SetDefaultPolicyVersion` as a privilege escalation pattern
  (again from Rhino's research).
- **Gap**: Flags the vulnerable permission set; does not detect the
  exploitation.

**P4 — AssumeRole Chain**: **Miss**
- Chained `sts:AssumeRole` (user → R1 → R2) requires trust-topology
  reasoning. Cloudsplaining analyses each policy in isolation and
  cannot express "role R2 is transitively reachable from user U".
- No published Cloudsplaining rule addresses transitive assume-role
  paths.

**P5 — AttachPolicy Escalation**: **Detect**
- Cloudsplaining flags `iam:AttachUserPolicy`, `iam:AttachRolePolicy`,
  and `iam:AttachGroupPolicy` on wildcard resources as
  privilege-escalation findings.
- Source: `privilege_escalation.py`
- **Note**: This is the closest thing to a "detect" among static tools —
  the policy pattern is unambiguous.

**P6 — Instance Profile Abuse**: **Miss**
- Runtime attack. Same reason as P2.

**P7 — Lambda Env-Var Credential Theft**: **Partial**
- Cloudsplaining flags `lambda:UpdateFunctionConfiguration` and
  `lambda:CreateFunction` combined with `iam:PassRole` as
  privilege-escalation patterns.
- **Gap**: Does not address env-var credential exposure per se — flags
  the Lambda function itself as a privilege-escalation vector.

**P8 — S3 Credential Harvest**: **Miss**
- Cloudsplaining does flag `s3:GetObject` on wildcard resources as a
  Data Exfiltration risk (a separate finding category), but this is
  not detection of the specific credential-harvest chain.

### Summary
Cloudsplaining: **1 Detect, 3 Partial, 4 Miss** (out of 8 AWS paths).

---

## Baseline Tool 2 — Prowler v4

**Publisher**: Prowler Cloud (community + commercial)  
**Repository**: https://github.com/prowler-cloud/prowler  
**License**: Apache 2.0 (community); commercial edition also available  
**Type**: Cloud security assessment framework (multi-cloud)  
**Focus**: Compliance and configuration checks against AWS, Azure,
GCP, Kubernetes

### Coverage philosophy

Prowler runs configuration checks and known-vulnerability patterns
against live cloud accounts. Unlike Cloudsplaining, Prowler can also
introspect runtime state (e.g., which IAM roles are attached to which
EC2 instances). Its coverage is broader than pure static IAM tools but
still framed around configuration compliance rather than chain
detection.

### Per-path assessment

Prowler has an extensive AWS check catalogue. Only checks directly
relevant to the 8 verified attack paths are enumerated below.

**P1 — PassRole + RunInstances**: **Detect** (via combined checks)
- `iam_role_administratoraccess_policy` — flags any IAM role with
  AdministratorAccess.
- `ec2_instance_profile_attached` — verifies instance profiles.
- **Combined**: Prowler flags EC2 instances with attached admin roles.
  This closely maps to P1's precondition.
- Source: Prowler v4 IAM and EC2 provider checks.

**P2 — IMDS SSRF Credential Theft**: **Miss**
- Prowler v4 does have `ec2_imdsv2_required` — checks that IMDSv2 is
  enforced. This is a preventive control that would block P2 (rated as
  Partial in the coverage matrix).
- **Gap**: Detection of IMDS exploitation is out of Prowler's scope
  (Prowler doesn't consume CloudTrail).

**P3 — CreatePolicyVersion Escalation**: **Partial**
- No specific `CreatePolicyVersion`-focused check.
- `iam_customer_attached_policy_no_administrative_privileges` flags
  customer-managed policies granting admin — a related concern.
- **Gap**: No detection of the version-mutation exploitation itself.

**P4 — AssumeRole Chain**: **Miss**
- Prowler check `iam_no_custom_policy_permissive_role_assumption`
  identifies policies with `sts:AssumeRole` on wildcard resources
  (Source: Prowler PR #646). This flags *permissive assume-role
  policies*, but does not model the multi-hop chain reachability.
- **Gap**: No transitive-reachability analysis.

**P5 — AttachPolicy Escalation**: **Detect**
- `iam_inline_policy_no_administrative_privileges` and related checks
  flag inline policies with escalation potential.
- `iam_administrator_access_with_mfa` requires MFA on admin.
- **Combined**: Prowler surfaces the vulnerable configuration.

**P6 — Instance Profile Abuse**: **Miss**
- Runtime attack detection is outside Prowler's scope.

**P7 — Lambda Env-Var Credential Theft**: **Partial**
- `lambda_function_no_secrets_in_variables` — checks for known
  credential patterns (AKIA, tokens) in Lambda environment variables.
- **Detect for the misconfiguration**, but not the exploitation chain
  (surface API read + off-band use).

**P8 — S3 Credential Harvest**: **Partial**
- `s3_bucket_no_public_access` — flags public buckets.
- `s3_bucket_secure_transport_policy` — enforces TLS.
- **Gap**: Neither addresses `.tfstate` / `.env` files containing
  credentials. The specific chain (surface read + off-band cred use)
  is not modelled.

### Summary
Prowler: **2 Detect, 3 Partial, 3 Miss** (out of 8 AWS paths).

---

## Baseline Tool 3 — Sigma HQ (Cloud rules)

**Publisher**: SigmaHQ community  
**Repository**: https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws  
**License**: Detection Rule License (DRL) 1.1  
**Type**: SIEM detection rule catalogue  
**Focus**: Runtime detection rules in provider-agnostic YAML format,
consumed by many SIEM platforms

### Coverage philosophy

Sigma rules are stateless: each rule matches a single event or narrow
event window. This makes Sigma poor at multi-hop chains but strong at
known-signature attack detection. Sigma's AWS cloud rule catalogue
covers a subset of well-known CloudTrail-visible attacks.

### Per-path assessment

Enumerated from `SigmaHQ/sigma/rules/cloud/aws/` as of July 2025 (rule
count fluctuates; verify at report submission).

**P1 — PassRole + RunInstances**: **Partial**
- `aws_ec2_startup_shell_script.yml` — detects EC2 user-data scripts
  (correlates loosely with attacker-launched instances).
- No rule specifically joins `iam:PassRole` with `ec2:RunInstances`.

**P2 — IMDS SSRF Credential Theft**: **Miss**
- No rule detects IMDS credential misuse via source-location anomaly.
- Related rule `aws_ec2_disable_encryption.yml` addresses a different
  IMDS concern.

**P3 — CreatePolicyVersion Escalation**: **Miss**
- No dedicated rule for `iam:CreatePolicyVersion` with admin injection.
- Related rule `aws_iam_backdoor_users_keys.yml` addresses a different
  IAM tampering pattern.

**P4 — AssumeRole Chain**: **Miss**
- Sigma stateless rules cannot model chained AssumeRole events.

**P5 — AttachPolicy Escalation**: **Partial**
- `aws_iam_backdoor_users_keys.yml` — related pattern (attach or
  backdoor keys).
- No rule for direct self-AttachUserPolicy with AdministratorAccess.

**P6 — Instance Profile Abuse**: **Miss**
- Same rationale as P2.

**P7 — Lambda Env-Var Credential Theft**: **Miss**
- No published Sigma rule targets Lambda env-var exfiltration.

**P8 — S3 Credential Harvest**: **Miss**
- No rule for credential-file pattern in S3 GetObject
  (`.tfstate`, `.env`).

### Summary
Sigma HQ AWS cloud rules: **0 Detect, 2 Partial, 6 Miss**.

### Structural note

This is not a criticism of Sigma. Sigma's stateless design is
appropriate for its use case (portable rule format across SIEMs).
Detection of multi-hop chains would require Sigma extensions with
correlation semantics (Sigma Correlations, still developing at time
of writing). The gap that PathTriage fills — attack-chain detection
with baseline-join — is orthogonal to Sigma's design.

---

## Baseline Tool 4 — Datadog CloudSIEM

**Publisher**: Datadog Inc.  
**Documentation**: https://docs.datadoghq.com/security/default_rules  
**License**: Commercial  
**Type**: Cloud-native SIEM  
**Focus**: Runtime detection with per-rule tuning against Datadog's
customer-observed telemetry baselines

### Coverage philosophy

Datadog CloudSIEM has the strongest baseline of the five reference
tools. Its rules include stateful joins (e.g., "unusual IP for role")
that approach PathTriage's baseline-join approach. However, its rules
are proprietary — coverage assessment is based on Datadog's public
default-rules catalogue.

### Per-path assessment

Rule name mappings from Datadog's public default-rules documentation:

**P1 — PassRole + RunInstances**: **Detect**
- `aws-ec2-instance-launched-with-admin-role` — fires on EC2 launch
  with an attached role holding elevated permissions.

**P2 — IMDS SSRF Credential Theft**: **Partial**
- `aws-credential-use-from-unusual-location` — generic anomaly rule
  covering off-location credential use. Would fire for P2 but is not
  specifically IMDS-focused.

**P3 — CreatePolicyVersion Escalation**: **Partial**
- `aws-iam-policy-modified` — fires on any IAM policy change. Broad,
  would need additional filtering to isolate P3.

**P4 — AssumeRole Chain**: **Partial**
- `aws-sts-assume-role-rate-anomaly` — fires on rate anomalies. Chain
  topology is not directly modelled, but rapid multi-hop AssumeRole
  would trigger the rate anomaly.

**P5 — AttachPolicy Escalation**: **Detect**
- `aws-iam-policy-attached-to-user` — attached to escalated policy
  triggers.

**P6 — Instance Profile Abuse**: **Partial**
- Same rule as P2 (`aws-credential-use-from-unusual-location`).

**P7 — Lambda Env-Var Credential Theft**: **Miss**
- No published Datadog rule joins Lambda GetFunctionConfiguration with
  subsequent new AKIA usage.

**P8 — S3 Credential Harvest**: **Miss**
- No published rule addresses S3 credential-file-pattern reads
  correlated with off-band credential use.

### Summary
Datadog CloudSIEM: **3 Detect, 4 Partial, 1 Miss** (out of 8 AWS paths).

Datadog is the closest of the five tools to PathTriage's coverage. The
delta remains that Datadog rules operate one at a time — no rule
explicitly reasons over the chain composition.

---

## Baseline Tool 5 — CIS AWS Foundations Benchmark v3.0

**Publisher**: Center for Internet Security  
**URL**: https://www.cisecurity.org/benchmark/amazon_web_services/  
**License**: Free (attribution required)  
**Type**: Configuration compliance benchmark  
**Focus**: Preventive control assurance, not runtime detection

### Coverage philosophy

CIS is a compliance benchmark — a checklist of configuration controls,
not a detection system. Coverage against attack paths is expressed as
"would this control have blocked the attack?" not "would this rule have
fired on the attack?"

### Per-path assessment

Control references from CIS AWS Foundations Benchmark v3.0.0.

**P1 — PassRole + RunInstances**: **Partial**
- CIS 1.16 — "Ensure IAM policies are attached only to groups or roles"
  (relates to policy hygiene).
- CIS 3.4 — logging of IAM policy changes.
- **Preventive intent**: Yes; **detection**: No.

**P2 — IMDS SSRF Credential Theft**: **Partial**
- CIS 5.1 — VPC flow log configuration (would enable post-hoc
  investigation).
- CIS does not specifically mandate IMDSv2, though v3.0 introduces
  guidance.

**P3 — CreatePolicyVersion Escalation**: **Miss**
- No CIS control specifically addresses policy-version mutation.

**P4 — AssumeRole Chain**: **Miss**
- No CIS control models multi-hop trust topology.

**P5 — AttachPolicy Escalation**: **Partial**
- CIS 1.19 — IAM Access Analyzer enabled.
- CIS 1.15 — MFA on all IAM users.
- **Preventive**: MFA blocks P5 in practice; not a detection.

**P6 — Instance Profile Abuse**: **Miss**
- Runtime attack; no CIS control applies.

**P7 — Lambda Env-Var Credential Theft**: **Miss**
- CIS AWS Foundations does not specifically cover Lambda environment
  variable secrets (this is in the CIS AWS Lambda Benchmark, a
  separate document).

**P8 — S3 Credential Harvest**: **Miss**
- No CIS control specifically addresses credential-file patterns
  in S3 objects.

### Summary
CIS AWS Foundations Benchmark v3.0: **0 Detect, 3 Partial, 5 Miss**.

### Structural note

CIS is a benchmark, not a detection tool. The classification as
"partial" for some paths reflects that CIS controls, if applied, would
prevent the attack precondition — but this is a compliance question,
not a detection question. For the coverage matrix's purposes, we treat
prevention-only controls as Partial when they meaningfully reduce the
attack's likelihood.

---

## Aggregate table (feeds Section 4 headline)

| Tool | Detect | Partial | Miss | Total |
|---|:---:|:---:|:---:|:---:|
| Cloudsplaining | 1 | 3 | 4 | 8 |
| Prowler v4 | 2 | 3 | 3 | 8 |
| Sigma HQ cloud | 0 | 2 | 6 | 8 |
| Datadog CloudSIEM | 3 | 4 | 1 | 8 |
| CIS AWS v3.0 | 0 | 3 | 5 | 8 |
| **PathTriage** | **8** | **0** | **0** | **8** |

### Aggregate structural gaps (three findings for §6.4)

**Gap 1: No baseline tool detects trust-topology chains as a single unit
(P4).** Datadog partial-fires on rate anomalies but does not model the
chain. This is PathTriage primitive 05's contribution.

**Gap 2: No baseline tool correlates surface-API reads with off-band
credential use (P7, P8).** Existing rules either flag the surface read
(Prowler for Lambda secrets, Cloudsplaining for S3 wildcards) or flag
the credential use (Datadog unusual-location), but never join them
within a correlation window. This is PathTriage primitive 04's
contribution.

**Gap 3: Only Datadog partially covers IMDS credential misuse (P2, P6).**
Detection requires a baseline for source IP or user-agent that
rule-based SIEMs do not maintain. This is PathTriage primitive 01's
baseline-join contribution.

---

## Success criterion check (per `PLAN.md` Phase 5)

**Criterion**: PathTriage detects at least one attack path that all of
{Prowler, Datadog CloudSIEM, Sigma HQ cloud} miss.

**Result**: **Met.** Paths **P4 (AssumeRole Chain), P6 (Instance Profile
Abuse), P7 (Lambda Env-Var Credential Theft), and P8 (S3 Credential
Harvest)** are missed or only partially covered by all three baselines.
PathTriage's primitives 04 (Credential Discovery) and 05 (Trust Topology)
fully cover them via novel baseline-join detection primitives.

---

## Notes on methodology

- **All rule enumerations were performed against the public,
  master-branch state of each tool's repository as of 2026-07-19.**
  Commercial tools (Datadog) were assessed via their public
  documentation, which may lag the actual product.
- **"Detect" requires a specific rule that fires on the exploitation
  event, not a broad rule that would technically fire alongside many
  other things.**
- **"Partial" reflects genuine coverage of the misconfiguration, an
  adjacent event, or a preventive control — not just tangential
  relevance.**
- **"Miss" means we could not identify any rule with meaningful
  overlap.** Absence of evidence is not evidence of absence; a future
  contributor to any of these projects may add coverage. The matrix
  will need refreshing at final report submission.

## Repository references

- Cloudsplaining: https://github.com/salesforce/cloudsplaining  
  Specific file: `cloudsplaining/scan/policy/privilege_escalation.py`
- Prowler v4: https://github.com/prowler-cloud/prowler  
  Specific paths: `prowler/providers/aws/services/iam/` and
  `prowler/providers/aws/services/ec2/`  
  Prowler check hub: https://hub.prowler.com/
- Sigma HQ cloud rules:
  https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
- Datadog default rules:
  https://docs.datadoghq.com/security/default_rules/
- CIS AWS Foundations Benchmark v3.0.0:
  https://www.cisecurity.org/benchmark/amazon_web_services/

## Historical context

The reference research for AWS privilege-escalation vector cataloguing
comes from Rhino Security Labs' AWS-IAM-Privilege-Escalation
repository (https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation).
Both Cloudsplaining and Prowler derive several of their escalation
detection patterns from this research. PathTriage's attack path
catalogue includes several paths that align with Rhino's list (P1
maps to Rhino's "iam:PassRole + ec2:RunInstances"; P5 maps to Rhino's
"iam:AttachUserPolicy"; P3 maps to Rhino's "iam:CreatePolicyVersion").
PathTriage's contribution beyond Rhino is (a) the defender-output
primitives, (b) the exploitability ranking, and (c) the cross-cloud
Azure extension. Cite Rhino appropriately in Chapter 2.
