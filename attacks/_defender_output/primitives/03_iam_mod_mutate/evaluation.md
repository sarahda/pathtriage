# Primitive 03 — Evaluation Results

> Status: **stub — populated during Phase 4** (evaluation execution).

## Reference corpus

- Positive corpus: PathTriage attack lab P3, replayed against evaluation
  AWS account.
- Negative corpus: `PATHTRIAGE_CORPUS_V=<TBD>` (100k events/day × 7 days,
  seed 42).
- Query parameters:
  - `:lookback_hours = 24`
  - `:baseline_days = 180`
  - `:correlation_window_sec = 300`
  - `:mass_attach_threshold = 3`

## Results

| Path | TP | FP | FN | Precision | Recall | MTTD (s) |
|---|---|---|---|---|---|---|
| P3 | ? | — | ? | — | ? | ? |
| **Aggregate** | ? | ? | ? | ? | ? | ? |

## Success criteria check

Per `methodology/evaluation_protocol.md` §6:

- [ ] Recall ≥ 0.9 on P3
- [ ] Precision ≥ 0.95 at 100k/day baseline rate
- [ ] Median MTTD ≤ 60 seconds

## Notes on expected FP behaviour

The 100k/day negative corpus includes ~1 legitimate `CreatePolicyVersion`
per day (`baseline_generation.md` §4.3). The baseline generator does not
model legitimate admin-action-adding version updates by default; these
are considered rare in practice (organisations more commonly refine
existing scope rather than expand it, or expand via new policies not
in-place modification).

Expected fire behaviour on benign corpus:

- **High-confidence fires** (`self_benefit_admin_injection`): near-zero
  benign rate. Requires the caller to hold the policy attached; this
  combination is not a legitimate ops pattern.
- **Medium-confidence fires** (`mass_elevation`): benign fire rate ≤ 1
  per week from current baseline. Occurs when a policy attached to many
  principals is legitimately expanded — rare.
- **Low-confidence fires** (`admin_injection`): benign fire rate depends
  on how the reference corpus models version updates to broad-scope
  policies. Expected ≤ 3 per week.

Confidence-tiered alerting is the primary FP mitigation. Precision
values will be reported separately for each tier.

## Sensitivity analysis (Phase 4)

- [ ] Correlation window = 60s (tight): recall =
- [ ] Correlation window = 3600s (loose): FP rate =
- [ ] Baseline window = 30d (short): recall =
- [ ] Baseline window = 365d (long): FP rate =
- [ ] Mass attach threshold = 1 (sensitive): FP rate =
- [ ] Mass attach threshold = 10 (specific): recall =

## Comparison to baseline tools

Per-tool detection status for P3 captured in `paths.md`. The
distinctive contribution of primitive 03 is the **version-delta
computation**: no comparison tool (Cloudsplaining, Prowler, Datadog,
Sigma, CIS) computes what changed between policy versions. Datadog's
undifferentiated CreatePolicyVersion rule illustrates the alternative
(fires on all events, unusable precision).

## Azure asymmetry note

Primitive 03's detection responsibility differs materially from its
Azure counterpart's, due to D-Z4-02 (undocumented Azure privilege-
escalation guard). On AWS, primitive 03 must fire on every syntactically
valid CreatePolicyVersion with admin content. On Azure, the equivalent
primitive only fires on mutations that Azure's guard did not silently
revert. This is documented in `azure_symmetry.md` as the primary
structural asymmetry between the two clouds' mutate primitives, and is
material to thesis §4 (Comparative Analysis).

Evaluation of primitive 03 does not attempt to measure Azure-side FP
rate — that is the W8 defender-output module's task. The AWS
evaluation stands on its own.
