# Primitive 05 — Evaluation Results

> Status: **stub — populated during Phase 4** (evaluation execution).

## Reference corpus

- Positive corpus: PathTriage attack lab P4, replayed against evaluation
  AWS account.
- Negative corpus: `PATHTRIAGE_CORPUS_V=<TBD>` (100k events/day × 7 days,
  seed 42).
- Query parameters:
  - `:lookback_hours = 24`
  - `:chain_window_min = 15`
  - `:baseline_days = 90`
  - `:min_chain_length = 2` (tuned to catch P4 at exactly 2-hop chain)

## Results

| Path | TP | FP | FN | Precision | Recall | MTTD (s) |
|---|---|---|---|---|---|---|
| P4 | ? | — | ? | — | ? | ? |
| **Aggregate** | ? | ? | ? | ? | ? | ? |

## Success criteria check

Per `methodology/evaluation_protocol.md` §6:

- [ ] Recall ≥ 0.9 on P4
- [ ] Precision ≥ 0.95 at 100k/day baseline rate
- [ ] Median MTTD ≤ 60 seconds

## Notes on expected FP behaviour

The 100k/day negative corpus includes ~25,000 daily AssumeRole events
(`baseline_generation.md` §4.2 CI/CD role assumptions category). Chain
reconstruction over 15-minute windows will produce many candidate chains:

- **Single-hop CI/CD** (user → DeployRole): most common, chain_length = 1,
  below `:min_chain_length` threshold. Not fired.
- **Two-hop CI/CD** (user → CIRole → DeployRole): common pattern in some
  organisations. If the chain signature is established (repeated daily),
  `chain_novel = FALSE` → not fired.
- **First-time two-hop combinations**: occasional new deployment paths.
  If terminal role is not admin, `admin_terminal = FALSE` and the fire
  is low-confidence only. Not surfaced as high-priority alert.

Expected fire rate per week on baseline:

- **High-confidence fires** (`admin_terminal_novel_chain`): near-zero.
  Requires a novel path to an admin-tagged role, which is a rare
  operational event.
- **Medium-confidence fires** (`novel_chain_novel_terminal`): ~ 2-5 per
  week. Legitimate first-time deployments to new services can trigger.
- **Low-confidence fires** (`novel_chain`): ~ 10-20 per week. High
  noise; deployed in monitoring mode, not alerting.

Confidence tiering is essential for this primitive due to the high
volume of legitimate AssumeRole activity.

## Sensitivity analysis (Phase 4)

- [ ] `:min_chain_length = 3`: recall on P4 =
      (P4 is exactly 2 hops, so raising threshold may miss it)
- [ ] `:chain_window_min = 60`: FP rate =
- [ ] `:baseline_days = 30` (short): recall =
- [ ] `:baseline_days = 180` (long): FP rate on established-chain baseline =

## Comparison to baseline tools

Per-tool detection status for P4 captured in `paths.md`. Three of five
comparison tools have partial coverage but none combines chain
reconstruction with novelty-based baseline. Datadog's undifferentiated
"multiple assumptions" rule fires on all CI/CD activity; Cloudsplaining
is policy-static; Prowler's chain check is static analysis.

Primitive 05's **novelty baseline** is the structural contribution.
Legitimate long-standing chains do not fire; only new traversals do.
This should yield significantly higher precision than the comparison
tools' undifferentiated rules at similar recall.

## Azure asymmetry note

Primitive 05 has the largest structural difference from its Azure
counterpart among all five primitives, per `azure_symmetry.md`:

- AWS: session-level chain via `sts:AssumeRole` self-join
- Azure: authorization-level cascade via role assignments + subsequent
  token acquisition correlation

The Azure W8 primitive will use a different query structure (correlation
ID joins across AAD sign-in events rather than AssumeRole self-join).
The detection concept is preserved; the SQL structure is not.

This is documented as an honest limitation of the "5 primitives cover
16 paths symmetrically" claim. Not all primitives translate identically
between clouds; some require cloud-specific query design while
preserving the primitive's semantics.
