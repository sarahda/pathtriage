# Related Work — Detection Tool Comparison

## Purpose

PathTriage's defender-output module must be positioned against existing cloud security detection tools. This document specifies the comparison methodology and captures the tools' coverage of the 8 AWS attack paths.

The comparison serves two report claims:

1. **Coverage gap**: at least one PathTriage-detected path is missed by all of {Prowler, Datadog CloudSIEM, Sigma HQ cloud}. Without this, PathTriage's primitive design has no defensible novelty over existing runtime detection.
2. **Structural difference**: static vs runtime, rule-based vs behavioural — PathTriage's primitives fit in a specific slot in the tool landscape, characterised here.

## 1. Selection criteria

The five tools were selected for the following properties:

- **Public rule sets**: rule catalogues are inspectable, so per-path coverage claims can be verified without live tool execution.
- **Cover both static and runtime detection**: static analysis catches misconfigurations that enable attacks; runtime detection catches attacks in progress. Both are legitimate defender surfaces.
- **Diverse deployment models**: open-source community tools (Prowler, Sigma), free-tier commercial (Cloudsplaining), commercial SIEM (Datadog), and compliance frameworks (CIS).
- **Currency**: all five have releases within the last 12 months (as of July 2026).

Excluded from comparison:

- **Wiz, Orca, Lacework** (commercial CNAPPs): rule catalogues are proprietary; cannot verify coverage claims without paid access.
- **CloudGoat**: attack lab, not a detection tool.
- **AWS GuardDuty**: managed detection with proprietary rules; findings are advertised but detection logic is not fully exposed.
- **Amazon Detective**: post-incident forensics, not detection.

## 2. Tools reviewed

### 2.1 Cloudsplaining (Salesforce)

Static analysis of IAM policies. Identifies risky permissions (privilege escalation, data exfiltration, resource exposure) by matching policy actions against a curated list.

- **Category**: static, misconfiguration-based
- **Rule source**: `cloudsplaining/shared/data/risky_iam_actions.yml` in the GitHub repo
- **Runtime observability**: none (does not consume CloudTrail)
- **Coverage extraction method**: for each of the 8 attack paths, check whether the misconfiguration the attack exploits (e.g., overly-broad `iam:AttachUserPolicy` in P5) appears in Cloudsplaining's risky-actions list. Mark `detect` if flagged, `partial` if the action is listed but scope conditions differ, `miss` if unlisted.

Cloudsplaining catches misconfigurations before an attack occurs; it does not observe the attack itself. In the coverage matrix, "detect" means "would have flagged the vulnerable configuration during policy review."

### 2.2 Prowler

Community-driven audit tool. Runs a suite of checks against an AWS account (or Azure/GCP) and reports policy violations, misconfigurations, and suspicious patterns.

- **Category**: audit-based, runs on-demand
- **Rule source**: `prowler-cloud/prowler` GitHub repo, `prowler/providers/aws/services/*` service-specific check modules
- **Runtime observability**: partial — Prowler v4 has some CloudTrail-based checks but is primarily configuration audit
- **Coverage extraction method**: search Prowler's check catalogue for each attack path's misconfiguration and for the exploitation event pattern. Mark `detect` / `partial` / `miss`.

### 2.3 Datadog CloudSIEM out-of-box rules

Commercial SIEM with published rule pack for AWS CloudTrail.

- **Category**: runtime detection, rule-based
- **Rule source**: docs.datadoghq.com/security/default_rules under the `aws` tag (~150 rules as of July 2026)
- **Runtime observability**: full CloudTrail ingestion
- **Coverage extraction method**: search rule catalogue for event-name matches against the exploitation events in each attack's `verification_log.txt`. Mark `detect` if a rule fires on the exploitation event, `partial` if a rule fires on a downstream side-effect but not the primary event, `miss` otherwise.

### 2.4 Sigma HQ cloud category rules

Community-maintained detection rule format with a large cloud-category rule set.

- **Category**: runtime detection, rule-based, backend-agnostic
- **Rule source**: `SigmaHQ/sigma` GitHub repo, `rules/cloud/aws/*.yml` (~80 AWS-specific rules as of July 2026)
- **Runtime observability**: applies to whatever backend consumes CloudTrail (Splunk, Elastic, etc.); pure rule specification
- **Coverage extraction method**: same event-name matching approach as Datadog. Sigma rules are simpler in structure (event name + `requestParameters` match), so coverage is often narrower than Datadog's but easier to reason about.

### 2.5 CIS AWS Foundations Benchmark v3.0

Compliance framework with prescriptive controls for AWS account hardening.

- **Category**: compliance-based, configuration audit
- **Rule source**: cisecurity.org/benchmark/amazon_web_services CIS AWS Foundations v3.0 (~50 controls)
- **Runtime observability**: none — pure configuration checks
- **Coverage extraction method**: for each attack path, check whether the misconfiguration required is prevented by a CIS control. Mark `detect` / `partial` / `miss` on prevention rather than detection (CIS's model is preventive).

## 3. Coverage matrix

To be populated during Phase 3 primitive build (each primitive's `paths.md` cross-references the coverage table). Skeleton:

| Path | Cloudsplaining | Prowler | Datadog | Sigma | CIS | PathTriage primitive |
|---|---|---|---|---|---|---|
| P1 (PassRole+RunInstances) | | | | | | 01 |
| P2 (IMDS SSRF) | | | | | | 01 |
| P3 (CreatePolicyVersion) | | | | | | 03 |
| P4 (AssumeRole Chain) | | | | | | 05 |
| P5 (AttachPolicy) | | | | | | 02 |
| P6 (Instance Profile Abuse) | | | | | | 01 |
| P7 (Lambda env-var theft) | | | | | | 04 |
| P8 (S3 credential harvest) | | | | | | 04 |

Cell values: `detect` (with source rule citation), `partial` (with note on what's covered), `miss`, or a rule ID for reference.

For each `miss` cell, a brief note in the primitive's `paths.md` explains **why** the tool misses — this is the material for the "structural gap" claim (§4).

## 4. Coverage aggregation

Two aggregate views produced in `evaluation_report.md`:

### 4.1 Path coverage per tool

Count paths detected (fully) by each tool:

| Tool | Paths detected | Miss reasons (summarised) |
|---|---|---|
| Cloudsplaining | ?/8 | pre-attack, no runtime |
| Prowler | ?/8 | config-focused, weak on IAM chain |
| Datadog CloudSIEM | ?/8 | rule-level; weak on baseline-anomaly |
| Sigma HQ | ?/8 | pure event-name match |
| CIS v3.0 | ?/8 | prevention-focused |
| **PathTriage** | **8/8** | **by construction — success criterion 1** |

### 4.2 Structural gap analysis

For each `miss` across all tools, identify whether the miss represents:

- **Detection lag** — tool could detect it with a rule update
- **Rule-model limitation** — tool cannot express the required condition (e.g., baseline-anomaly across historical events)
- **Category exclusion** — tool doesn't observe the relevant surface (e.g., no CloudTrail ingestion in static tools)

Attack paths whose `miss` is category (2) or (3) across all baseline tools are PathTriage's specific contribution. The evaluation report highlights at least one such path (per PLAN.md success criterion 4).

## 5. What PathTriage adds beyond each baseline

Anticipated contributions per baseline (to be validated in Phase 4):

- **Beyond Cloudsplaining**: runtime detection of exploitation, not just misconfiguration flagging.
- **Beyond Prowler**: convergence-based primitives (fewer rules covering more paths), baseline-aware joins (rule-model expressiveness).
- **Beyond Datadog CloudSIEM**: coverage of the IAM-modification mutate primitive (P3 / Z4), which Datadog's rule set treats as one rule together with assign — coverage confirmed only after Phase 4 evaluation.
- **Beyond Sigma HQ**: baseline-aware joins (Sigma rules are stateless event-name matches).
- **Beyond CIS v3.0**: exploitation detection (CIS is prevention-only) and coverage of paths where CIS's preventive controls are not implementable at the account level (e.g., cross-account trust topology).

The Azure symmetry contribution (D-Z4-02, D-Z4-03) is not comparable to any of these tools because none of them cover Azure. It enters thesis Section 4 independently of this related-work comparison.
