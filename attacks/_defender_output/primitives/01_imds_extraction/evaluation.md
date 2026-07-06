# Primitive 01 — Evaluation Results

> Status: **stub — populated during Phase 4** (evaluation execution).

## Reference corpus

- Positive corpus: PathTriage attack labs P1, P2, P6, replayed against
  the evaluation AWS account.
- Negative corpus: `PATHTRIAGE_CORPUS_V=<TBD>` (100k events/day × 7 days,
  seed 42).
- Query parameters:
  - `:lookback_hours = 24`
  - `:baseline_days = 30`
  - `:min_session_events = 5`

## Results

To be populated:

| Path | TP | FP | FN | Precision | Recall | MTTD (s) |
|---|---|---|---|---|---|---|
| P1 | ? | — | ? | — | ? | ? |
| P2 | ? | — | ? | — | ? | ? |
| P6 | ? | — | ? | — | ? | ? |
| **Primitive aggregate** | ? | ? | ? | ? | ? | ? |

## Success criteria check

Per `methodology/evaluation_protocol.md` §6:

- [ ] Recall ≥ 0.9 across P1, P2, P6
- [ ] Precision ≥ 0.95 at 100k/day baseline rate
- [ ] Median MTTD ≤ 60 seconds
- [ ] P6 not detected by all of {Prowler, Datadog CloudSIEM, Sigma HQ}
      → primitive contributes to module success criterion 4

## Sensitivity analysis (Phase 4)

- [ ] Rate = 10k/day: precision =
- [ ] Rate = 1M/day: precision =
- [ ] Baseline window = 7d (short): recall =
- [ ] Baseline window = 90d (long): FP rate =

## Comparison to baseline tools

Per-tool detection status for P1/P2/P6 is captured in `paths.md`
"Coverage matrix row". Aggregate comparison in `evaluation_report.md`
after all primitives are measured.
