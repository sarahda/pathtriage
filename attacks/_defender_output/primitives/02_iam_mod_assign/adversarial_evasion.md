# Primitive 02 — IAM Modification (Assign) — Adversarial Evasion

## Baseline signature

Fires on `iam:Attach*Policy` / `iam:Put*Policy` events where the assignment is an admin-equivalent policy AND at least one of: caller == target (self-attach), caller has no history granting this policy, or target had no prior admin-scope policy. Confidence tiered `high` (self-attach + admin) or `medium` (other conditions).

## Evasion candidates

### Evasion 1 — Attach a non-admin-tagged policy that grants admin actions

**Description**: attacker creates a custom policy named innocuously (e.g., `AppOperator`, `DataReader`) whose actions include `*` or `iam:*`. Attaches this custom policy to self. The policy ARN is not in the primitive's `admin_managed_policies` list; the query does not fire on it as admin-equivalent for the managed-attach path.

- **Capability cost**: Modest — attacker needs `iam:CreatePolicy` in addition to `iam:AttachUserPolicy`.
- **Operational cost**: Low — one extra API call before the attach.
- **Detection-elsewhere cost**: Medium — the `iam:CreatePolicy` event itself is unusual for the caller and would be caught by a distinct primitive (custom policy creation), which the current module does not include but which is a natural extension.
- **Blind attacker likelihood**: Unlikely — real-world attackers reach for `AdministratorAccess` by name.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: for managed policies, the inline-policy detection path (Step 2's `admin_equivalent` check on `inline_policy_doc`) does not apply because the custom policy is a managed policy with its ARN in the target's policies. However, if the same attacker uses `iam:PutUserPolicy` with an inline wildcard, the inline-detection path fires. The full evasion requires the attacker to use `CreatePolicy + AttachUserPolicy` chain, defeating primitive 02's current detection.

**Mitigation**: primitive 02 should be extended in future work with a custom-policy-content analysis join — read the policy document at attach time and score its wildcard content. Deferred to W7-W9 or thesis future-work section.

### Evasion 2 — Attach to a different identity, then assume that identity

**Description**: attacker attaches `AdministratorAccess` to role B (not the caller's identity). Then assumes role B via `sts:AssumeRole`. Uses admin access as role B. The `self_attach` flag is FALSE (caller ≠ target); the fire falls to `medium` confidence via `target_no_prior_admin`.

- **Capability cost**: Modest — attacker needs `iam:AttachRolePolicy` on role B and `sts:AssumeRole` for role B's trust policy.
- **Operational cost**: Low — one extra step.
- **Detection-elsewhere cost**: Low — the assume-role event is separately visible but not directly correlated by primitive 02.
- **Blind attacker likelihood**: Unlikely — takes more thought than self-attach.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: `medium` confidence fire on `target_no_prior_admin` still catches this. Recall is preserved; precision drops because the primitive fires on more cases. This is the intended trade-off of the confidence-tiered output.

### Evasion 3 — Spread grants over time to establish caller history

**Description**: attacker performs many small legitimate-looking policy attachments over the baseline window (90 days) to establish themselves as a routine caller before the admin attach. Defeats the `unestablished_caller` condition.

- **Capability cost**: Modest — requires ongoing IAM access over 90 days.
- **Operational cost**: High — 90-day timeline unusable for most attack scenarios.
- **Detection-elsewhere cost**: Medium — each warm-up assignment is itself visible; a defender doing periodic IAM audits catches the caller's evolving pattern.
- **Blind attacker likelihood**: Never.
- **Graybox attacker likelihood**: Unlikely.
- **Whitebox attacker likelihood**: Possible (only for high-value long-lived compromise).

**Residual detection**: even with warm-up, the `self_attach + admin_equivalent` conditions still fire independent of caller history. The evasion only bypasses the `medium`-confidence path.

### Evasion 4 — Inline policy with obfuscated wildcards

**Description**: attacker uses `iam:PutUserPolicy` with an inline policy whose actions list includes `iam:List*`, `iam:Get*`, `iam:Simulate*`, `iam:Update*` etc. — many narrowly-scoped `iam:*` sub-wildcards that together add up to admin-equivalent without matching the primitive's wildcard pattern `iam:*` literally.

- **Capability cost**: Modest — requires knowledge of IAM action namespace.
- **Operational cost**: Low.
- **Detection-elsewhere cost**: Low.
- **Blind attacker likelihood**: Unlikely.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: primitive 02's inline-policy detection matches `%iam:*%` (any iam-wildcard substring), so `iam:Update*` matches. Similarly, `%"Action":%"*"%` matches full wildcards. Selective sub-wildcards (`iam:List*` alone, without any full-wildcard) can evade — but a policy with only sub-wildcards is not admin-equivalent by itself, so the attack degrades to a partial-privilege escalation that a separate check on the target's total policy scope would still catch.

## Summary — Whitebox Evasion Landscape

| Evasion | Reachable | Cost bar |
|---|---|---|
| 1. Custom-named policy with wildcards | ✓ | Modest capability, low operational |
| 2. Attach to different identity + assume | ✗ (medium confidence still fires) | — |
| 3. Long-timeline warm-up | ✗ (self-attach + admin still fires) | — |
| 4. Selective sub-wildcards | ~ (degrades to partial privilege) | Modest |

**Primitive 02 has one low-cost whitebox evasion (Evasion 1)**: custom-named policy with wildcard content. This is honestly reported and mapped to a future extension (custom-policy-content analysis). The other three evasions either fail (residual conditions still fire) or have high operational cost.

For blind and graybox attackers, primitive 02 is highly effective — the `self_attach + admin_equivalent` path fires on the vast majority of naive privilege-escalation attempts.
