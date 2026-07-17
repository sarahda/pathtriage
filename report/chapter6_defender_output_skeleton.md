# Chapter 6 — Defender-Output Module

**Target length**: 5–6 pages
**Status**: Skeleton (2026-07-17). First draft: W8 Sat (2026-07-25).

---

## 6.1 Introduction (~0.75 page)

### Opening claim
Offensive tools that enumerate IAM attack paths without corresponding
defensive artifacts leave the operational cycle incomplete. Defenders
still need to translate "here is a path that exists" into "here is a
detection rule I can deploy and a preventive control I can attach."

### Gap in existing tools (motivate the module's inclusion)
Cite tools table from Chapter 2:
- Cloudsplaining: static IAM analysis, no runtime signal
- Prowler: compliance checks, not attack-path detection
- PMapper: enumeration only, no output for SOC workflow
- BloodHound (Cloud): visualisation, not deployable rules

**The 3-way asymmetry**: offensive research produces attack-path
catalogues (PMapper, IAM Vulnerable, HackTricks). Compliance tooling
produces configuration checks (CIS, Prowler). Detection engineering
produces SIEM rules (Sigma). No tool synthesises all three from a
verified attack-path corpus.

### PathTriage's contribution
Each verified attack path is packaged with (a) a detection primitive
that fires on the exploitation event, and (b) a preventive control
snippet (SCP or Azure Policy) that structurally blocks it. Detection
primitives are shared across attack paths at their convergence points —
this compression is the module's design principle.

### Chapter roadmap
Section 6.2 — Design: 5 primitives + 3.2:1 compression ratio.
Section 6.3 — Methodology: pre-registered evaluation protocol.
Section 6.4 — Evaluation results: TP/FP/MTTD/coverage.
Section 6.5 — Limitations and future work.

---

## 6.2 Design (~1.5 pages)

### Convergence-based primitive design
Explain the design decision: N attack paths → M primitives (M < N)
via shared exploitation signature.

**Table 6.1 — Convergence mapping (from root README)**

| Primitive | Coverage | Compression |
|---|---|---|
| 01 IMDS extraction | P1, P2, P6 (AWS) + Z1, Z8 (Azure) | 5:1 |
| 02 IAM mod assign | P5 (AWS) + Z3 (Azure) | 2:1 |
| 03 IAM mod mutate | P3 (AWS) + Z4 (Azure) | 2:1 |
| 04 Credential discovery | P7, P8 (AWS) + Z5, Z6 (Azure) | 4:1 |
| 05 Trust topology | P4 (AWS) + Z7 (Azure) | 2:1 |
| **Total** | **16 paths → 5 primitives** | **3.2:1** |

### Baseline-join detection design
Each primitive is not a stateless rule. Detection requires joining
against a historical baseline — the caller's session UA history, the
instance's egress IP set, the target policy's prior versions, etc.

Contrast with stateless SIEM rules (Sigma HQ), which cannot express
"unusual for this specific session" without producing high FP rates.

### Preventive control pairing
Each primitive folder holds a companion `scp_snippet.json` (AWS) or
`azure_policy.json`. The preventive control structurally prevents the
exploit; the detection primitive catches the exploit when the control
is not in place or has an exception.

**Example**: primitive 01's SCP denies IMDSv1 org-wide. IMDSv2 
enforcement blocks P2 entirely (SSRF cannot elevate to IMDS access).
Detection catches P1 and P6, where legitimate IMDS access is expected
but subsequent credential use is anomalous.

### Cross-cloud symmetry as validity check
Each primitive requires an identifiable Azure signal correspondence.
Referenced in `azure_symmetry.md` per primitive. Symmetry is not a
deliverable — KQL implementation deferred — but structural equivalence
is documented (e.g., primitive 03's ARM `roleDefinitions/write` event
mirrors CloudTrail `CreatePolicyVersion`).

---

## 6.3 Methodology (~1 page)

### Pre-registered evaluation
Methodology authored before any primitive is built (per
`methodology/evaluation_protocol.md`, committed 2026-07-06). This is
unusual for detection-engineering evaluations, which are typically
retrofit-scored. Pre-registration prevents primitive design from
subtly optimising against known corpus artefacts.

### Corpus design
- **Positive corpus**: 23 events across 8 attack labs, each labelled
  with `attack_id`, `step`, `expected_primitive` for scoring.
- **Negative corpus**: 700,000 events over 7 days, generated per
  `baseline_generation.md`. Rate (100k/day) drawn from AWS's own
  CloudTrail volume references, Duo Labs public dataset, and this
  project's AWS account traffic.
- **Anchoring**: 8 human personas, 3 CI/CD service accounts, 20
  stable EC2 instance IDs, persistent IP/UA pairs. Anchoring is
  what makes baseline-join queries realistic.

### Metrics
Per spec §2:
- **Precision** = TP / (TP + FP) at event-fire level
- **Event recall** = TP / (TP + FN) per primitive
- **Attack recall** = detected_paths / covered_paths per primitive
  (new metric — argued for below)
- **MTTD** = seconds from first attack event to first fire

### Argument for attack-level recall
Event-level recall penalises primitives for not firing on recon or
post-exploit exercise steps. Both are outside the exploitation-event
scope by design. The operationally meaningful question — "did the
primitive fire at least once on each attack?" — is captured by
attack-level recall.

### Execution engine
DuckDB against JSONL corpora that mirror CloudTrail Lake v1.09 schema
exactly. Cost-controlled and byte-reproducible. Production validation
against CloudTrail Lake itself is scheduled for W8 Fri (2026-07-24)
with no expected semantic drift.

### Comparison-baseline coverage matrix
Static analysis of five reference tools' published rule sets against
the 8 AWS attack paths. Rule-level source per tool documented in
`related_work.md` §3.

---

## 6.4 Evaluation Results (~1.5 pages)

### Headline table (pull from evaluation_report.md)

**Table 6.2 — Per-primitive evaluation (700k benign + 23 attack events)**

| Primitive | Paths | Fires | TP | FP | FN | Precision | Event Recall | Attack Recall | MTTD |
|---|---|---|---|---|---|---|---|---|---|
| 01 IMDS | 3 | 8 | 8 | 0 | 1 | 1.000 | 0.889 | 1.000 | 15.0s |
| 02 IAM assign | 1 | 1 | 1 | 0 | 1 | 1.000 | 0.500 | 1.000 | 12.0s |
| 03 IAM mutate | 1 | 1 | 1 | 0 | 2 | 1.000 | 0.333 | 1.000 | 10.0s |
| 04 Cred disc | 2 | 4 | 4 | 0 | 2 | 1.000 | 0.667 | 1.000 | 9.0s |
| 05 Trust topo | 1 | 2 | 2 | 0 | 1 | 1.000 | 0.667 | 1.000 | 0.0s |
| **Macro** | **8** | | | | | **1.000** | **0.611** | **1.000** | **9.2s** |

### Discussion (this is where the reader learns)

**Precision claim.** Every primitive achieves precision = 1.0 across
700k benign events at 100k events/day rate. The IMDS extraction
primitive alone processed 122k IMDS-pattern events (S3 application
role access + long-tail application traffic) and produced zero false
positives. This validates the baseline-join design over stateless
rule matching.

**Event vs attack recall.** Event-level recall of 0.611 macro is not
a coverage gap. The false-negative class is entirely recon or
post-exploit exercise steps (e.g., `ListUsers` after chain
completion, `ListFunctions` before Lambda env-var read). These
events are outside the exploitation scope by design. Attack recall
of 1.000 confirms that every covered path is detected at least once.

**MTTD.** Mean detection time is 9.2 seconds. Two paths (P4 chain,
P6 instance profile abuse) detect at the first attack event itself
(MTTD = 0). P1 (PassRole + RunInstances) shows 45s MTTD because the
first attack event (`RunInstances` by IAMUser) is out of scope;
detection begins at step 2 when the instance's role credentials are
used off-box.

### Comparative coverage (Table 6.3 — condensed)

| Tool | Detect | Partial | Miss |
|---|:---:|:---:|:---:|
| Cloudsplaining | 1/8 | 3/8 | 4/8 |
| Prowler | 2/8 | 3/8 | 3/8 |
| Datadog CloudSIEM | 3/8 | 4/8 | 1/8 |
| Sigma HQ | 0/8 | 2/8 | 6/8 |
| CIS v3.0 | 0/8 | 3/8 | 5/8 |
| **PathTriage** | **8/8** | 0 | 0 |

### Structural gaps in existing tools
1. **No baseline tool detects trust-topology chains as a single unit**
   (P4). Primitive 05 contributes this coverage.
2. **No baseline tool correlates surface-API reads with off-band
   credential use** (P7, P8). Primitive 04 contributes this
   coverage.
3. **Only Datadog partially covers IMDS credential misuse** (P2, P6).
   Baseline-join detection is PathTriage primitive 01's contribution.

---

## 6.5 Limitations and Future Work (~0.75 page)

### Synthetic-baseline realism
Reported precision is a lower bound on real-traffic precision.
Coverage claims are unaffected (they depend only on positive
corpus). Real-traffic validation is future work.

### Event-level recall as design signal
Some readers may prefer event-level as their operational metric.
The design decision to optimise for attack-level detection instead
is documented; a future primitive variant could widen scope to recon
events at the cost of precision. Trade-off is not explored here.

### Adversarial evasion out of scope
Evaluation assumes attacker executes attacks as documented in
`exploit.py`. Evasion strategies per primitive are documented
qualitatively in `adversarial_evasion.md` but not scored. This is
a multi-month project on its own scale.

### Rate sensitivity
Reference corpus is 100k events/day. Sensitivity at 10k and 1M
events/day is future work — the generator supports these rates
directly.

### CTL production validation
DuckDB replay validated logic and corpus. CTL production
validation (W8 Fri) is the final step to establish real-defender-
workflow parity.

### Cross-cloud symmetry as full deliverable
Azure primitives are structurally documented but not KQL-implemented.
KQL implementation and Azure baseline generation are T3 scope.

---

## Draft-writing notes (for me, W8 Sat)

- Open Section 6.1 with a specific practitioner scenario, not
  abstraction. E.g., "A SOC lead running Prowler weekly sees 43
  privilege escalation flags. Which ones are exploitable?"
- Reuse breach case studies from Chapter 1 (Capital One IAM chain,
  Snowflake) — refer back, don't repeat.
- Section 6.4 discussion should be 3 paragraphs, not bullets. Prose
  wins here.
- The 3 structural gaps (§6.4) can become Section 4 Structural
  Asymmetries findings — decide when writing Section 4 whether they
  belong there or here.
- Cite `evaluation_report.md` for full numbers; body table shows
  headline only.
