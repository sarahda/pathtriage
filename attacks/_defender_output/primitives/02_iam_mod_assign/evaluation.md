# Primitive 02 — Evaluation Results

> Status: **stub — populated during Phase 4** (evaluation execution).

## Reference corpus

- Positive corpus: PathTriage attack lab P5, replayed against evaluation
  AWS account.
- Negative corpus: `PATHTRIAGE_CORPUS_V=<TBD>` (100k events/day × 7 days,
  seed 42).
- Query parameters:
  - `:lookback_hours = 24`
  - `:baseline_days = 90`
  - Admin policy ARNs: 5 built-in AWS managed policies (see query)

## Results

| Path | TP | FP | FN | Precision | Recall | MTTD (s) |
|---|---|---|---|---|---|---|
| P5 | ? | — | ? | — | ? | ? |
| **Aggregate** | ? | ? | ? | ? | ? | ? |

## Success criteria check

Per `methodology/evaluation_protocol.md` §6:

- [ ] Recall ≥ 0.9 on P5
- [ ] Precision ≥ 0.95 at 100k/day baseline rate
- [ ] Median MTTD ≤ 60 seconds

## Notes on expected FP behaviour

The 100k/day negative corpus includes ~1 legitimate
`AttachRolePolicy` per day where the attached policy is an AWS-managed
policy (`baseline_generation.md` §4.3). If the attached policy is
`AdministratorAccess` (rare but plausible in benign ops), the
`unestablished_caller` and `target_no_prior_admin` conditions may both
be TRUE, producing a medium-confidence fire.

Expected FP characterisation:

- High-confidence fires (`self_attach_admin`): near-zero benign rate.
  Self-attach of admin policies is not a legitimate ops pattern.
- Medium-confidence fires (`new_caller_grants_admin`,
  `target_elevated`): benign fire rate depends on how the reference
  corpus models new-service-onboarding events. Expected ≤ 3 per week
  from the current baseline generator.

Confidence-tiered alerting is the primary FP mitigation. Precision
values will be reported separately for `high` and `medium` tiers.

## Sensitivity analysis (Phase 4)

- [ ] Rate = 10k/day: precision =
- [ ] Rate = 1M/day: precision =
- [ ] Baseline window = 30d (short): recall =
- [ ] Baseline window = 180d (long): FP rate =

## Comparison to baseline tools

Per-tool detection status for P5 captured in `paths.md`. Aggregate
comparison in `evaluation_report.md` after all primitives are measured.

The distinctive contribution of primitive 02 vs Datadog/Sigma is the
**self-attach + baseline-anomaly combination**. Datadog fires on admin
attach regardless of caller; Sigma fires on `AttachUserPolicy` events
generically. Primitive 02's confidence-tiered output should demonstrate
substantially higher precision than either at similar recall.
