# Primitive 04 — Evaluation Results

> Status: **stub — populated during Phase 4** (evaluation execution).

## Reference corpus

- Positive corpus: PathTriage attack labs P7, P8, replayed against evaluation
  AWS account.
- Negative corpus: `PATHTRIAGE_CORPUS_V=<TBD>` (100k events/day × 7 days,
  seed 42).
- Query parameters:
  - `:lookback_hours = 24`
  - `:correlation_window_min = 60`
  - `:key_id_novelty_window_hours = 24`

## Results

| Path | TP | FP | FN | Precision | Recall | MTTD (s) |
|---|---|---|---|---|---|---|
| P7 | ? | — | ? | — | ? | ? |
| P8 | ? | — | ? | — | ? | ? |
| **Aggregate** | ? | ? | ? | ? | ? | ? |

## Success criteria check

Per `methodology/evaluation_protocol.md` §6:

- [ ] Recall ≥ 0.9 on P7 and P8
- [ ] Precision ≥ 0.95 at 100k/day baseline rate
- [ ] Median MTTD ≤ 60 minutes (correlation window bound)

## Notes on expected FP behaviour

The 100k/day negative corpus includes:

- ~5,000/day S3 `GetObject` events (`baseline_generation.md` §4.4). Of these,
  the fraction matching credential-file patterns should be near zero in a
  well-organised account. Baseline generator does not include `.tfstate` or
  `.env` files in benign S3 paths, so FP fires on the read side are expected
  to be zero.
- ~50/day `GetFunctionConfiguration` events (long-tail category). Fires on
  the read side are zero unless a Lambda function coincidentally has env
  vars matching credential patterns.
- ~150/day new access keys or STS sessions (CI/CD role assumptions). These
  are the primary FP driver — CI/CD's short-lived session tokens produce
  "new access key ID" events at a rate of ~15/day for correlation windows
  of 60 min. The IP/UA correlation join is the primary filter.

Expected FPs are dominated by:

- Cross-primitive coincidences (S3 GetObject + STS session created
  independently within 60 min sharing an IP) — expected < 1/day.

Confidence tiering: `high` fires require both novelty and IP+UA share;
`medium` fires require both shares without novelty. Precision reported
per tier.

## Sensitivity analysis (Phase 4)

- [ ] Correlation window = 15 min (tight): recall =
- [ ] Correlation window = 240 min (loose): FP rate =
- [ ] Access-key novelty window = 6h (short): FP rate =
- [ ] Access-key novelty window = 72h (long): recall =
- [ ] Add credential-file patterns beyond current list: recall =

## Comparison to baseline tools

Per-tool detection status for P7 and P8 captured in `paths.md`.

**P7 is missed by 4 of 5 comparison tools**. Prowler has partial coverage
via compliance scan. No comparison tool provides runtime detection of
Lambda env-var credential leak use.

**P8 has broader partial coverage** across 4 of 5 tools, but no tool ties
the object read to subsequent access-key use — the correlation is
primitive 04's structural contribution.

Both paths contribute to module success criterion 4 (at least one path
missed by all commercial baselines): P7 unambiguously satisfies the
criterion.

## Azure asymmetry note

Primitive 04's detection surface coverage differs from its Azure
counterpart's, per `azure_symmetry.md`:

- AWS: small credential-storage surface set (Lambda env vars, S3
  patterns). Complete coverage in the query.
- Azure: broader surface set (App Service, Function App, Key Vault,
  Storage keys, Automation Accounts, etc.). W8 Azure primitive covers
  Z2/Z5/Z6 but full parity requires more work.

Azure benefits from cleaner attribution (SP `AppId` vs AWS access-key-ID)
and better precision on Key Vault (per-secret logging vs AWS
per-config-blob). AWS benefits from smaller surface set (fewer edge
cases). Neither is uniformly superior; both need cloud-specific tuning.
