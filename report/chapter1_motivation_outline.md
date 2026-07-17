# Chapter 1 — Motivation

**Target length**: 4–5 pages
**Status**: Outline (2026-07-17). First draft: W7 Tue (2026-07-15)... but Tue = today done. First draft: W7 Wed evening (2026-07-16).

---

## Opening paragraph (target 5 sentences)

Draft direction: put the reader inside a specific SOC seat before any
abstraction. Example structure:

> Sentence 1: "On [date], a [specific breach] began with [specific IAM 
>              action]."
> Sentence 2: "By the time the intrusion was detected, [attacker had
>              done X to Y systems]."
> Sentence 3: "The path from initial credential to full compromise
>              involved [N] IAM permission transitions — each
>              individually permitted by policy."
> Sentence 4: "No existing tool would have flagged the chain as a
>              whole, because [tool class 1 does X, tool class 2 does
>              Y]."
> Sentence 5: "This thesis presents PathTriage, [one-line what it does]."

Candidate opening breach: **Capital One 2019** (most-cited, well-
documented, clear IAM chain).

---

## §1.1 The IAM Attack-Path Problem (target 1 page)

### 1.1.1 Recent breach case studies (3 cases, ~1 paragraph each)

**Capital One 2019** — Full IAM chain reconstruction from published
post-mortem:
- SSRF via misconfigured WAF → IMDSv1 access
- Instance role: `*-WAF-Role` with S3 permissions
- Enumeration of 30 S3 buckets, exfiltration of 106M records
- IAM permission per step was individually legitimate for the role
- Detection lag: 4 months

**Snowflake 2024** — Mass credential exposure via unenforced MFA:
- Compromised customer credentials via infostealer malware
- MFA optional per Snowflake's default — 165+ customer accounts affected
- Ticketmaster, AT&T, Santander among victims
- Attack chain: valid credentials → no MFA prompt → data warehouse
- IAM concept: multi-tenant credential surface without mandatory MFA

**Microsoft Midnight Blizzard 2024** — SPN token attack:
- Password spray → test OAuth app compromise
- Test app had permission to create OAuth apps in production tenant
- New app granted `full_access_as_app` to Exchange Online
- 8 months of email exfiltration before detection
- IAM concept: cross-boundary token issuance without scope validation
- **Relevant to primitives**: primitive 05 (trust topology chain)

Statistics as supporting evidence (not opening hook):
- Verizon DBIR 2024: [X]% of breaches involve identity abuse
- Palo Alto Unit 42: cloud identity misconfig is [X]th most common
  IR trigger
- IBM Cost of Data Breach 2024: identity compromise adds $[X]M
  average cost

### 1.1.2 Why this matters as a research problem

Move from case studies to the underlying pattern:
- Each breach involved a chain of permissions, not a single grant
- Chain-level analysis is possible in principle but absent in practice
- Blue teams face "which of these 500 flagged paths matters?"
- Ranking is the missing piece between enumeration and action

---

## §1.2 Gap Analysis (target 1.5 pages)

### 1.2.1 Enumeration ≠ triage

Concrete example: PMapper's output size on a mid-size AWS account.
- Cite [environment: 50 roles, 30 users, 20 policies]
- PMapper output: [N] potential escalation paths
- SOC practitioner cannot review [N] paths per week
- Ranking would reduce [N] to top 10 daily

### 1.2.2 Existing tools by category

**Static IAM analysis** (Cloudsplaining, PMapper):
- What they solve: enumeration of permission-graph paths
- What they don't: exploitability ranking, defender output
- Gap: SOC-ready ranking

**Compliance tooling** (Prowler, CIS Benchmarks, ScoutSuite):
- What they solve: known-bad-config enumeration
- What they don't: novel paths, chain analysis
- Gap: paths not in any config check

**Commercial CNAPP** (Wiz, Orca, Datadog CloudSIEM):
- What they solve: enterprise-scale posture + runtime detection
- What they don't: transparent methodology, open source
- Gap: closed source, accessibility for smaller orgs

**Attack path research** (BloodHound Cloud, PurpleCloud):
- What they solve: red team enumeration
- What they don't: defender output, deployable rules
- Gap: research → practitioner translation

### 1.2.3 The unfilled gap

The intersection of {ranking, defender output, transparency, cross-
cloud} is not populated. PathTriage occupies this gap.

Include coverage-matrix preview table (small version of Chapter 2's
full table).

---

## §1.3 Timeliness — Why Now (target 0.75 page)

### 1.3.1 Multi-cloud as default

- 89% of enterprises use 2+ clouds (Flexera 2024 State of the Cloud)
- Cross-cloud attack paths are the new normal (Wiz research 2024)
- No open-source tool covers AWS + Azure attack paths comparatively

### 1.3.2 Regulatory pressure

- SOC 2 Trust Services Criteria 2022 updated CC6.6 (identity ranking)
- ISO 27001:2022 Annex A.5.15 (access control monitoring)
- PCI-DSS 4.0 requirement 7 (least privilege, quarterly review)
- All require documentable IAM triage; none prescribe methodology

### 1.3.3 Blue team resource constraint

- 3M cyber workforce gap globally (ISC² 2024)
- Manual review of enumeration output does not scale
- Automation is required, not optional

---

## §1.4 Contributions (target 0.5 page)

Numbered contributions, each ~1 sentence to describe, ~1 sentence 
each on evidence:

1. **Ranked attack-path discovery**. A rubric (exploitability +
   asset-value + complexity + observability) ranks discovered paths.
   Rubric weights are calibrated with domain expert input where
   possible.

2. **Cross-cloud comparative catalogue**. 16 verified attack paths
   (8 AWS + 8 Azure), executed end-to-end in isolated labs, with
   sanitized verification logs committed. Enables comparative
   findings such as D-Z4-02 (Azure's structural blocking of SP-to-SP
   OBO) and D-Z6-01 (Azure Storage Account Key Operator RBAC gap).

3. **Defender-output module**. Per-primitive detection rules
   (CloudTrail Lake SQL + KQL scaffolding) and preventive controls
   (SCP + Azure Policy snippets), packaged with the attack catalogue.
   Empirically evaluated: precision 1.000, attack recall 1.000 across
   700k benign + 23 attack events.

4. **Open-source availability**. Full reproducibility from seed +
   spec. Terraform + exploit.py + evaluation harness committed.
   Enables independent replication.

5. **Methodological contribution**. Pre-registered evaluation
   protocol; per-primitive design decisions traced via decision logs;
   attack-level vs event-level recall distinction documented.

---

## Section-level notes for W7 Wed draft writer (me)

- Chapter 1 is where the "why" happens. Don't skimp on breach cases.
- Each subsection opens with WHY before WHAT. Reversed order is
  wooden.
- Statistics live in supporting sentences, not opening sentences.
- Voice: first-person plural throughout ("we present", "we found").
- Length budget check: 4–5 pages = ~2500 words. Current outline
  supports 3000+. Cut ruthlessly if overrunning.
- Time budget: 2 days (W7 Wed evening + W7 Thu evening after
  chapter 2 rewrite). Draft is v0, polish is W9.
- Refer to `attacks/_defender_output/evaluation/evaluation_report.md`
  for §1.4 contribution 3's numbers — do not re-derive.
