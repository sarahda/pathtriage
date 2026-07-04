# Defender-Output Module — Build Plan

**Total budget**: 14 hours across 3 sessions.
**Prerequisite**: PathTriage AWS catalogue (P1–P8) verified. ✓ Complete.
**Deliverable**: 5 detection primitives, each with query + SCP + per-path signature + evasion + Azure symmetry + evaluation.

## Phase 1 — Methodology (4 hours, first build session)

Establishes measurement framework before any primitive is written. This ordering is deliberate: primitive design decisions (e.g., baseline-join dimension choices) depend on the evaluation protocol.

- [ ] **`methodology/evaluation_protocol.md`** (1.5 h)
    - TP/FP definitions with reference to positive/negative CloudTrail corpora
    - Precision, recall, F1, MTTD formulas
    - Coverage-vs-baselines methodology (per-primitive)
    - Reproducibility: seed control, event-rate parameterisation
    - Threats to validity: synthetic-baseline limitations, adversary-model scope
- [ ] **`methodology/baseline_generation.md`** (1 h)
    - Synthetic CloudTrail event generator spec (Python, output = JSON lines in CTL schema)
    - Realistic event-mix approximation (small-to-medium enterprise: ~100k events/day)
    - Event categories: read-heavy console browsing, CI/CD role assumptions, dev-ops IAM changes, S3 access patterns
    - Distribution parameters, seed control, corpus versioning
- [ ] **`methodology/related_work.md`** (1 h)
    - Cloudsplaining coverage (policy-static)
    - Prowler rule inventory (audit-based)
    - Datadog CloudSIEM out-of-box rules (commercial detection)
    - Sigma HQ cloud category rules (community)
    - CIS AWS Foundations v3.0 (compliance-based)
    - Coverage matrix template: rows = 8 paths, cols = tools, cells = detected/missed/partial
- [ ] **`methodology/adversarial_evasion.md`** (0.5 h)
    - Evasion cost taxonomy: cost = (attacker capability required, operational overhead, detection risk elsewhere)
    - Per-primitive evasion analysis template
    - Threat-model bounding: what is out-of-scope (e.g., data-plane evasion via VPC endpoints)

## Phase 2 — Primitive 1 as canonical build (3 hours, second build session)

Primitive 1 (IMDS extraction) is the largest coverage primitive (3 paths: P1, P2, P6). It is built fully so the template is fixed before the remaining four are built in parallel.

- [ ] **`primitives/01_imds_extraction/README.md`** (0.5 h)
    - Detection rationale
    - Coverage claim: P1 (PassRole + RunInstances), P2 (IMDS SSRF), P6 (Instance Profile Abuse)
    - Baseline-join dimension: caller-VM binding (IMDS credentials should only surface CloudTrail events where the caller-ARN maps back to the issuing instance's role)
- [ ] **`primitives/01_imds_extraction/cloudtrail_lake_query.sql`** (1 h)
    - Full CTL SQL, including baseline join
    - Comments explaining each clause
    - Tuning parameters: lookback window, anomaly threshold
- [ ] **`primitives/01_imds_extraction/scp_snippet.json`** (0.3 h)
    - Preventive SCP: `imds:*` IP conditions, IMDSv2-only enforcement
- [ ] **`primitives/01_imds_extraction/paths.md`** (0.4 h)
    - Per-path detection signature (P1, P2, P6)
    - Signal specificity per path
- [ ] **`primitives/01_imds_extraction/adversarial_evasion.md`** (0.4 h)
- [ ] **`primitives/01_imds_extraction/azure_symmetry.md`** (0.4 h)
    - Signal correspondence: Azure `AzureActivity` with MI principal binding
    - Asymmetry note: KQL detail deferred to W8

## Phase 3 — Primitives 2–5 in parallel-template mode (4 hours, third build session)

With the primitive 1 template fixed, the remaining primitives are 1 hour each (7 files × ~8 min = ~1h). Each follows the primitive 1 file structure exactly.

- [ ] **Primitive 02 — IAM modification (assign)**: P5
- [ ] **Primitive 03 — IAM modification (mutate)**: P3
    - Note: Azure symmetry page here documents D-Z4-02 (Azure privilege-escalation guard) as an asymmetry: AWS provides only detection, Azure adds structural prevention.
- [ ] **Primitive 04 — Credential discovery**: P7, P8
- [ ] **Primitive 05 — Trust topology**: P4

## Phase 4 — Evaluation execution (2 hours, third or fourth session)

- [ ] Generate synthetic baseline corpus per `methodology/baseline_generation.md` (~30 min)
- [ ] Replay 8 attack labs into CloudTrail Lake (~20 min; labs already exist)
- [ ] Run each primitive's CTL query against combined corpus, count TP/FP per primitive (~40 min)
- [ ] Compute precision/recall/F1/MTTD per primitive (~15 min)
- [ ] Compare with three baselines' coverage of the same 8 paths (~15 min)
- [ ] **`evaluation_report.md`** — aggregate results table + per-primitive analysis

## Phase 5 — Integration and cleanup (1 hour)

- [ ] Cross-references from each attack `attacks/0X_*/README.md` back to its covering primitive
- [ ] Root README refinement based on measured results
- [ ] Commit + push

## Session Suggestion

- **Day 1 (~5 h)**: Phase 1 complete + Phase 2 start (primitive 1 README + query)
- **Day 2 (~5 h)**: Phase 2 finish + Phase 3 primitives 02–03
- **Day 3 (~4 h)**: Phase 3 primitives 04–05 + Phase 4 evaluation + Phase 5 integration

## Success Criteria

The module is complete when:

1. Every one of the 8 verified AWS attack paths is covered by exactly one primitive (no gaps, no double-counting).
2. Every primitive has a runnable CTL query, a preventive SCP snippet, an evasion analysis, an Azure signal correspondence, and a measured TP/FP evaluation.
3. Coverage vs the three chosen baselines is documented in a single table showing PathTriage's primitives detect ≥ the union of baseline coverage.
4. The evaluation report identifies at least one primitive where PathTriage detects a path that all three baselines miss (otherwise the contribution is unclear).
5. Cross-references from each attack path README to its covering primitive exist and are consistent.
