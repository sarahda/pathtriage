# Exploitability Rubric v1 — Specification

**Status**: v1 weights per module docstring; calibration against supervisor ranking scheduled W8 (2026-07-21 window).

## Inputs

Four ordinal (1-5) attributes per discovered attack path.

### d_edge — per-edge difficulty
- 1: trivial (single IAM API call with common permissions)
- 3: standard (documented technique, common exploit path)
- 5: specialist (requires undocumented internals or specific chain)

Computed as `round(mean(EDGE_DIFFICULTY[rel] for each edge))` clamped to [1, 5].

### h — hop count
- 1: single edge (direct)
- 5: 5+ hops

Computed as `min(5, len(path.edges))`.

### delta_p — privilege delta
- 1: lateral only, no scope change
- 3: scope broadened but not to admin
- 5: reaches AdministratorAccess or equivalent (`iam:*`, `*:*`)

Computed by matching target node label against `ADMIN_POLICY_KEYWORDS`.

### d_det — detection difficulty
- 1: loud (fires common CloudTrail alerts)
- 3: mixed
- 5: silent (blends with legitimate operations)

Computed by inspecting edge relation set (heuristic).

## Scoring formula
Score = 0.30 * (6 - d_edge)      # easy edges -> high
+ 0.20 * (6 - h)            # short chains -> high
+ 0.30 * delta_p            # more privilege -> high
+ 0.20 * d_det              # harder to detect -> high

Domain: [1.0, 5.0]. Weights sum to 1.0.

## Weight rationale (v1, pre-calibration)

| Weight | Value | Rationale |
|---|---|---|
| W_EDGE (d_edge) | 0.30 | Per-edge difficulty is the primary predictor of whether an attack is realistically executable |
| W_HOP (h) | 0.20 | Hop count matters (each additional step adds friction) but less than per-step difficulty |
| W_DELTA (delta_p) | 0.30 | Consequence severity — a trivial path to admin is worse than a hard path to lateral |
| W_DET (d_det) | 0.20 | Detection difficulty matters but is subordinate to feasibility + severity |

These weights are prior beliefs. Calibration against Lachlan Jones's independent path ranking (W8, 16 paths, Spearman rho >= 0.75 threshold) will either confirm or refine them. If refinement is required, weights are re-fit via ordinary least squares against the supervisor's rank order and re-committed as v1.1.

## Not in scope for v1

- Business context (asset value at target) — v2 candidate
- Time-of-day / TTPs matching — out of scope
- MITRE ATT&CK cloud technique tagging — future work
- Per-tenant customisation — future work
