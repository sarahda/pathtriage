# Evaluation Protocol

## Purpose

This document defines how each detection primitive is measured. It is authored **before** any primitive is built because primitive design decisions (baseline-join dimensions, query lookback windows, threshold parameters) depend on the evaluation semantics defined here.

The protocol supports three claims per primitive:

1. **Coverage** — which of the 8 verified AWS attack paths does this primitive detect?
2. **Precision on realistic traffic** — what is the false-positive rate against a synthetic benign CloudTrail corpus sized to a small-to-medium enterprise?
3. **Comparative value** — does this primitive detect paths that Cloudsplaining, Prowler, Datadog CloudSIEM, Sigma HQ cloud rules, and CIS AWS Foundations Benchmark v3.0 miss?

## 1. Corpora

### 1.1 Positive corpus (attack traffic)

The positive corpus is the CloudTrail event stream produced by replaying each of the eight verified attack labs (`attacks/0[1-8]_*/`). Each lab is a self-contained Terraform scenario + `exploit.py`. The `verification_log.txt` in each attack directory captures the specific control-plane calls each attack makes; the positive corpus is the union of those calls across all eight labs, tagged with the source path.

Each event in the positive corpus is labelled with:

- `pathtriage.attack_id` — one of `P1`..`P8`
- `pathtriage.step` — attack step index (used for MTTD computation)
- `pathtriage.expected_primitive` — the primitive expected to fire on this event (per the convergence mapping in the root README)

Labels are metadata used only for scoring; they are not visible to the primitive queries.

### 1.2 Negative corpus (benign baseline)

The negative corpus is synthetic CloudTrail events representing benign enterprise activity. Its generation is specified in `baseline_generation.md`. Summary parameters:

- **Volume**: ~100,000 events per day (small-to-medium enterprise reference; see baseline_generation.md §2.1 for justification)
- **Duration**: 7-day corpus (700k events total)
- **Category mix**: read-heavy console browsing, CI/CD role assumptions, dev-ops IAM changes, S3 access patterns, EC2 lifecycle events, long-tail low-frequency actions
- **Realism**: event names, service-side response codes, and userIdentity structure conform to CloudTrail schema; principal names, IPs, and resource ARNs are stable across the corpus so baseline-join queries have realistic historical anchors

Synthetic (rather than real replayed) traffic is chosen because reproducibility, cost control, and seed-controlled variance are all measurable in synthetic data and not in captured production traffic. This trade-off is examined in §5.1.

### 1.3 Comparison baseline corpora

The five comparison tools are evaluated against the **same positive corpus** used for PathTriage primitives. Their coverage claims are extracted from their published rule sets, not from live tool execution, because:

- Static tools (Cloudsplaining, CIS) do not consume CloudTrail; their coverage is expressed as "would this tool have flagged the misconfiguration the attack exploits."
- Runtime tools (Prowler, Datadog, Sigma) publish rule catalogues that we can inspect for event-name and condition overlap.

Specific extraction methodology per tool is in `related_work.md` §3.

## 2. Metrics

### 2.1 True positive / false positive definitions

An **event-level fire** is a single CloudTrail event that matches a primitive's query condition. All metrics are computed at event-fire level, not at alert-cluster level, because alert clustering is a downstream defender concern outside PathTriage's scope.

- **True positive (TP)**: a fire on an event whose `pathtriage.attack_id` label is set, and whose `pathtriage.expected_primitive` matches the firing primitive.
- **False positive (FP)**: a fire on an event whose `pathtriage.attack_id` label is empty (i.e., benign corpus event). **Strict interpretation**: any fire on benign traffic is a FP, regardless of semantic similarity to attack signature. Rationale: from the defender's operational perspective, a fire is an alert that requires human review; near-miss fires cost the same as unrelated fires.
- **False negative (FN)**: a positive-corpus event whose `pathtriage.expected_primitive` matches the primitive under evaluation, but which did not fire.
- **True negative (TN)**: benign-corpus events that did not fire. TN count is |negative corpus| − FP, tracked implicitly.

Cross-primitive fires (e.g., an IMDS-extraction event that also fires the IAM-modification primitive because of a shared field) are counted **per primitive independently**. A single event can be TP for one primitive and FP for another. This is intentional: the module's contribution is per-primitive validity, not aggregate deduplicated alerting.

### 2.2 Precision, recall, F1

Standard definitions applied per primitive:

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 · Precision · Recall / (Precision + Recall)

Reported per primitive and aggregated across the five primitives (macro-averaged, since primitives cover different numbers of paths).

### 2.3 Mean time to detect (MTTD)

MTTD is measured from **attack start** — the timestamp of the first event with a given `pathtriage.attack_id` — to the first fire on any event of that attack. Rationale: attacks in progress can still be stopped; MTTD measured from attack start reflects operational containment potential, not post-hoc forensic capability.

- **MTTD per path**: for each attack path P, min over path P's events of (fire time − attack start time), taken over the primitive that covers P.
- **MTTD per primitive**: mean of MTTD values for all paths the primitive covers.

MTTD units: seconds, since positive-corpus events are timestamped at their real execution time from `verification_log.txt`.

An attack path with no fire (FN) contributes ∞ to MTTD — reported separately as "detection failure" rather than folded into the mean.

### 2.4 Coverage-vs-baselines

Reported at two levels:

- **Path-level**: for each of the 8 attack paths × 5 comparison tools + PathTriage, mark detect / miss / partial. Partial = tool flags the misconfiguration but not the exploitation event, or flags one step of a multi-step attack.
- **Rule-level**: appendix table mapping specific comparison-tool rules to PathTriage primitives via event-name overlap. Used to identify structural gaps (e.g., "no baseline tool covers roleDefinitions/write mutation").

Path-level enters thesis Section 4 body. Rule-level enters appendix.

The success criterion for the module (per PLAN.md Phase 5) is that PathTriage's primitives detect at least one attack path that all three of {Prowler, Datadog CloudSIEM, Sigma HQ cloud} miss. This gate is checked in the aggregate evaluation report.

## 3. Measurement procedure

### 3.1 Corpus replay into CloudTrail Lake

Each attack lab is deployed and its `exploit.py` executed with `--tf-output` pointing to the deployed lab state. CloudTrail events flow to a dedicated CTL event data store scoped to the PathTriage evaluation account. Event ingestion latency (~2–15 min per AWS) is treated as measurement noise; corpus replay is followed by a 30-min settling window before queries run.

Attack labs are executed **serially**, not in parallel, so `pathtriage.attack_id` labelling by CloudTrail ingestion time is unambiguous.

### 3.2 Per-primitive query execution

Each primitive's `cloudtrail_lake_query.sql` is executed against the combined corpus (positive + negative) in the CTL event data store. Query lookback window is set per primitive; typical value is 24 hours (justified per primitive in `primitives/NN_*/README.md`).

Fires are captured as the query result set. Each result row is joined by `eventID` back to the labelled corpus to determine TP/FP/FN status.

### 3.3 Result aggregation

For each primitive:

1. Run query. Collect fire set F.
2. For each fire f ∈ F, look up label. Classify as TP or FP.
3. For each labelled event with matching `expected_primitive` not in F, count as FN.
4. Compute precision, recall, F1, MTTD.
5. Record in `primitives/NN_*/evaluation.md`.

Aggregate results roll up into `evaluation_report.md` at the module root.

## 4. Reproducibility

### 4.1 Seed control

Synthetic benign corpus generation uses a fixed seed (`PATHTRIAGE_BASELINE_SEED=42`, documented in `baseline_generation.md`). Re-running with the same seed produces the same corpus byte-for-byte. This is required so measurement runs are comparable across time (e.g., re-running after a primitive refinement should show the difference caused by the refinement, not by corpus variance).

Positive corpus is fully deterministic (Terraform scenarios + `exploit.py` are deterministic given the same account state).

### 4.2 Event-rate parameterisation

The `~100k events/day` baseline rate is a parameter, not a fixed constant. Sensitivity to this rate is analysed in §5.1 by re-running measurements at 10k/day and 1M/day and reporting how precision, recall, and F1 shift.

### 4.3 Corpus versioning

Each corpus is tagged with a version string (`PATHTRIAGE_CORPUS_V=YYYY-MM-DD.N`) written into every event's `pathtriage.corpus_version` field. Evaluation reports cite the corpus version used. If the negative-corpus generator or the positive-corpus attack labs change, the version increments; prior evaluation results are marked stale.

## 5. Threats to validity

### 5.1 Synthetic-baseline limitations

The negative corpus is synthetic. Real enterprise CloudTrail streams contain event patterns not captured by the generator — bespoke automation, third-party SaaS integrations, misconfigured legacy tooling. The extent to which PathTriage's precision generalises to real traffic is bounded by the generator's realism.

Mitigation: baseline generation categories (`baseline_generation.md` §4) are informed by AWS's published CloudTrail volume references, three public CloudTrail sample corpora (AWS Well-Architected blog, Duo Labs public dataset, Elastic Security public samples), and the author's own AWS account traffic during the PathTriage build (which is small but real). Where synthetic categories diverge from these sources, the divergence is documented.

Un-mitigated limitation: FP rate reported here is a lower bound on real-traffic FP rate. Coverage claims (path detection) are unaffected because they depend only on the positive corpus.

### 5.2 Adversary-model scope

The evaluation assumes an attacker who executes the verified attacks as documented in each `exploit.py`, without adversarial evasion attempts. Evasion is analysed separately per primitive (`primitives/NN_*/adversarial_evasion.md`) but not folded into the headline precision/recall.

Rationale: measuring evasion-adjusted precision requires an evasion corpus, which is a multi-month project on its own scale. The current evaluation measures baseline-attacker detection; the adversarial evasion analysis is qualitative.

### 5.3 Single-tenant vs multi-tenant assumption

All events (positive + negative) originate in a single AWS account. Cross-account attack paths (P4 AssumeRole Chain, when the chain crosses accounts) are executed within a single account with two-role hop rather than a genuine cross-account trust. Detection primitives that depend on inter-account context (e.g., unexpected external principal) are validated against the labelled positive corpus but not against a multi-tenant baseline.

Real multi-account environments would produce a richer trust-topology positive corpus. This limitation is called out in the trust-topology primitive's evaluation notes.

## 6. Success criteria for the module

The module passes evaluation when all of the following hold:

1. Every primitive achieves recall ≥ 0.9 on its assigned paths (no primitive silently misses a path it is supposed to cover).
2. Every primitive achieves precision ≥ 0.95 against the negative corpus at the reference event rate (100k/day). Precision below this threshold means the primitive is too noisy for operational use.
3. Median MTTD across primitives ≤ 60 seconds. Attacks that take longer than the attack itself to detect are not useful.
4. PathTriage detects ≥ 1 attack path that all of {Prowler, Datadog CloudSIEM, Sigma HQ cloud} miss. This ensures the module provides value beyond community/commercial baselines.
5. Rule-level coverage matrix identifies at least one structural gap in existing tools that PathTriage fills. This is the qualitative counterpart of criterion 4.

Failure of any criterion is reported honestly in `evaluation_report.md` and, if the failure is fundamental (e.g., recall < 0.9 for a primitive despite tuning), the primitive is redesigned rather than shipped with a caveat.
