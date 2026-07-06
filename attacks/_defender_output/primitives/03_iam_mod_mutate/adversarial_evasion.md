# Primitive 03 — IAM Modification (Mutate) — Adversarial Evasion

## Baseline signature

Fires on `iam:CreatePolicyVersion` events where the new policy version contains admin-equivalent actions, the prior default version did not, AND the new version is activated (either via subsequent `SetDefaultPolicyVersion` within 5 min or setAsDefault=true on the create call). Confidence tiered: `high` (caller self-benefit), `medium` (mass attachment), `low` (attribution unclear).

## Evasion candidates

### Evasion 1 — Multi-version stepwise elevation

**Description**: attacker performs several `CreatePolicyVersion` calls over hours or days, each adding non-admin actions individually harmless (e.g., v2 adds `s3:*`, v3 adds `ec2:*`, v4 adds `iam:List*`, v5 adds `iam:Pass*`, v6 adds `iam:Attach*`). Each step's delta is below admin-equivalent, but cumulatively the policy is admin-equivalent. Primitive's per-step delta check does not fire because no single step introduces `"*"` or `iam:*`.

- **Capability cost**: None — attacker already has `CreatePolicyVersion` for the base attack.
- **Operational cost**: Medium — requires 5-10 API calls spread over some duration.
- **Detection-elsewhere cost**: Medium — the pattern of many CreatePolicyVersion calls on the same policy in a short window is itself unusual and would be caught by a distinct primitive on version-churn rate.
- **Blind attacker likelihood**: Unlikely — attackers reach for the fastest path.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: primitive 03 currently checks single-step deltas. Extension to cumulative-delta scoring (compare current version against v1 or against a snapshot) closes this evasion; documented as future work in `evaluation_report.md`. In the current state, primitive 03 has a known blind spot for stepwise elevation over long windows.

**Note**: this evasion has a temporal signature — many CreatePolicyVersion calls in a short window — that a version-churn primitive would catch. Not implemented in the current module but noted for extension.

### Evasion 2 — Modify a policy the caller does not appear to hold

**Description**: attacker mutates a customer-managed policy attached to a different principal (e.g., a service role used by an internal application). The caller_holds_policy check returns FALSE. Fire drops from `high` to `medium` or `low` confidence.

- **Capability cost**: None — attacker uses their existing `CreatePolicyVersion` permission.
- **Operational cost**: Low.
- **Detection-elsewhere cost**: Medium — the mutated policy's assignees suddenly have admin permissions, and those assignees' subsequent behaviour is anomalous. Downstream primitives on unexpected-privilege-use catch it.
- **Blind attacker likelihood**: Unlikely — attackers usually self-benefit directly.
- **Graybox attacker likelihood**: Possible — an attacker who knows about the caller-holds-policy check may deflect blame.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: `medium` confidence fire (mass_elevation) still catches this when the mutated policy has attach_count ≥ threshold. `low` confidence fire (admin_injection) catches all remaining cases. Recall is preserved; precision drops. This is the intended trade-off of the confidence-tiered output.

### Evasion 3 — Create the new admin version, wait, then activate

**Description**: attacker calls `CreatePolicyVersion` at time T (creating an inactive version). Waits 6 minutes (past the 5-minute correlation window). Then calls `SetDefaultPolicyVersion` to activate. Primitive 03's Case A correlation fails.

- **Capability cost**: None — no new capability.
- **Operational cost**: Low — 6 minutes.
- **Detection-elsewhere cost**: None.
- **Blind attacker likelihood**: Never — no reason to wait if you're not thinking about detection.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: this evasion **defeats the current 5-minute correlation window**. Mitigation is straightforward: extend `:correlation_window_sec` to 1 hour (3600) or 4 hours (14400). Cost is more false positives on legitimate ops where create-and-review-and-activate takes minutes. Precision-vs-recall trade-off documented in `evaluation.md` sensitivity analysis.

Alternative mitigation: detect the CreatePolicyVersion with admin content immediately (fire on Create alone if content is admin-equivalent), regardless of activation. Precision is lower (inactive versions never elevate anyone) but recall is higher. Deployment decision.

The current primitive defaults to 5-minute correlation as a balance point. Deployment guidance in `README.md` §Preventive Control notes that longer windows suit low-op-tempo accounts.

### Evasion 4 — Encode wildcards to bypass substring match

**Description**: primitive's admin-detection uses LIKE substring matching (`%"Action":%"*"%`, etc.). Attacker constructs policy documents that grant equivalent scope without matching these substrings — e.g., 400 explicit non-wildcard actions listed by name, or unusual JSON formatting that defeats simple LIKE.

- **Capability cost**: Modest — requires enumerating admin-equivalent action lists (public information but tedious).
- **Operational cost**: Low — one large policy document.
- **Detection-elsewhere cost**: Low.
- **Blind attacker likelihood**: Never — attackers reach for wildcards for reason.
- **Graybox attacker likelihood**: Unlikely.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: LIKE substring matching is genuinely evadable. A rigorous JSON-parse-and-diff implementation defeats this evasion but requires computation more suited to a stored procedure or backing script than pure SQL. Deferred to Phase 4 improvement — if evaluation reveals this evasion in practice, the primitive is upgraded to JSON-parse semantics.

Current state: primitive detects the common case (attacker writes `"Action": "*"`); high-effort attackers can craft encoded equivalents to evade. Honest disclosure in `evaluation_report.md`.

## Summary — Whitebox Evasion Landscape

| Evasion | Reachable | Cost bar |
|---|---|---|
| 1. Stepwise multi-version elevation | ✓ | Medium op cost, medium det-elsewhere |
| 2. Modify different principal's policy | ✗ (medium confidence still fires) | — |
| 3. Wait past 5-min window | ✓ | Very low |
| 4. Encoded non-wildcard admin equivalence | ✓ | Modest capability |

**Primitive 03 has three whitebox evasions with realistic cost bars.** This is more than primitive 01 or 02, reflecting the complexity of policy-content analysis. Mitigations exist for each:

- Evasion 1: version-churn primitive extension (future work)
- Evasion 3: parameter tuning + optional immediate-on-create fire mode
- Evasion 4: JSON-parse-and-diff implementation (Phase 4 improvement if measured need)

For blind and graybox attackers — the majority of real-world adversaries — primitive 03 is effective on the `"Action": "*"` pattern that constitutes 90%+ of naive privilege-escalation attempts (per informal survey of red-team writeups and CTF solution archives).

## Comparison to Primitive 01 evasion analysis

Primitive 01's evasion landscape was dominated by one low-cost whitebox evasion (SSH tunnel from compromised instance). Primitive 03 has three, with a common theme: **policy content analysis is genuinely hard in SQL**, and attackers who know the primitive's implementation details can construct evasions that a JSON-aware detector would not miss.

The report's Discussion section (thesis §5) argues that primitives requiring content analysis (like mutate) benefit from a two-layer defence: SQL-based fast detection at ingestion time, plus a slower JSON-parsing verifier for high-confidence fires. This is the pattern deployed by mature commercial SIEMs (e.g., Datadog Workflows for post-detection enrichment). Primitive 03 documents where this pattern would help.
