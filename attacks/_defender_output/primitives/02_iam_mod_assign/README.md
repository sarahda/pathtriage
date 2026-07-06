# Primitive 02 — IAM Modification (Assign)

## Coverage

This primitive covers one verified AWS attack path:

| Path | Attack | Assign action |
|---|---|---|
| P5 | AttachPolicy Escalation | Self-attach of AWS-managed `AdministratorAccess` (or equivalent broad policy) to the caller's own user/role via `iam:AttachUserPolicy` / `iam:AttachRolePolicy` |

The primitive also detects the closely-related `iam:PutUserPolicy` / `iam:PutRolePolicy` (inline policy assignment) since the two API families produce structurally identical elevation with a different persistence model (inline lives on the identity itself; attached policies live independently). Both are equally serious.

## Why this primitive is separate from Primitive 03 (mutate)

The AWS IAM-modification class was collapsed to a single primitive in the midway report. During Z4 verification, the class was split into two structurally distinct primitives with different CloudTrail event surfaces and different detection signatures. **This is primitive 02 (assign)**; primitive 03 covers mutation.

- **Assign** (this primitive): binds an *existing* policy or role to an *existing* principal. Affects one principal at a time. **Creates a new IAM record** — visible in `iam:ListAttachedUserPolicies` afterwards.
- **Mutate** (primitive 03): rewrites the actions inside an *existing* policy. Affects **every** principal that already has the policy attached, retroactively. **Creates no new attachment record** — invisible to attachment audits.

A defender detecting only one of the two primitives sees only half the IAM-modification class. Treating them as one primitive collapses two independently-detectable signals (see `paths.md` for the coverage-tool comparison that demonstrates this).

## Detection Rationale

Legitimate IAM assignment is common in enterprise operations: new microservices need roles, new employees need permissions, environments get provisioned. The `iam:AttachUserPolicy` / `iam:PutRolePolicy` events themselves are not attack signals.

The attack signature is a **privilege-delta anomaly**: the caller is granting an elevated policy (or an inline policy with elevated actions) to a target that previously did not hold anything equivalent. Two sub-conditions distinguish attack from operations:

1. **Self-attach**: caller == target. Attack pattern. Legitimate operations almost never self-elevate (except in edge cases like initial account setup or CI/CD bootstrapping, which are attributable to distinct principals).
2. **Elevation-delta**: the newly-attached policy grants actions the target did not have before. In P5, `AdministratorAccess` is attached where the target held only a narrow custom policy.

The baseline-join dimension is **caller-target-policy-history**. For each `iam:Attach*Policy` / `iam:Put*Policy` event:

- **Expected**: caller regularly grants this policy to targets of this class, and the target previously held policies of comparable scope.
- **Anomalous**: caller has never granted this policy to any target before, or the target has never held anything of this scope before.

## Baseline-Join Approach

Query joins the candidate event against three historical anchors:

1. **Caller history**: has this caller ever performed an `iam:Attach*Policy` on this policy ARN before? If yes and > baseline threshold, treat caller as an established policy-manager.
2. **Target scope history**: what policies has this target held in the last 90 days? Compute a policy-scope class (narrow / broad / admin) and check whether the new attachment escalates the class.
3. **Self-attach flag**: is `requestParameters.userName` (or `.roleName`) the same as `userIdentity.userName` (or the assumed role)? Independent flag; contributes strongly regardless of other conditions.

The primitive fires when any of: self-attach + scope-escalation, OR non-established-caller + scope-escalation, OR self-attach + inline policy with wildcard actions.

## Query Semantics

See `cloudtrail_lake_query.sql`. In prose:

```
For each CloudTrail event E in the last 24h where
    E.eventName ∈ {AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy,
                   PutUserPolicy, PutRolePolicy, PutGroupPolicy}

Extract:
    - caller: E.userIdentity.arn
    - target: E.requestParameters.{userName, roleName, groupName}
    - policy: E.requestParameters.policyArn (for Attach*) or
              the inline policyDocument (for Put*)

If caller == target (self-attach) AND policy has elevated actions:
    → fire (highest confidence)

If policy is admin-equivalent (AdministratorAccess, IAMFullAccess,
   PowerUserAccess, or inline with wildcard action)
   AND caller has never granted this policy before:
    → fire

If policy scope > target's historical maximum scope:
    → fire (baseline-anomaly)
```

## Coverage per Path

See `paths.md`. Summary:

- **P5**: attacker self-attaches `AdministratorAccess`. Fires with confidence "self-attach + admin policy" — the strongest signal in the query. MTTD ≈ seconds.

## Preventive Control

`scp_snippet.json` denies `iam:AttachUserPolicy` / `iam:AttachRolePolicy` when the target is the caller, using the `${aws:username}` variable. This is a structural prevention at the SCP layer.

The SCP does not prevent inline policy assignment on the caller (`iam:PutUserPolicy` with self-target) because SCPs cannot reliably match inline-policy targets in the same way — the target is a URL path element, not a policy variable-comparable field. Inline self-attach is caught only at detection.

**Residual risk**: an attacker with permission to assume a distinct role can bypass the SCP by having role A attach the policy to role B. This is closed by detection (the caller-target relationship is still auditable in CloudTrail) but not by the SCP alone.

## Evaluation Summary

Populated after Phase 4 execution. See `evaluation.md`.

## References

- Adversarial evasion: `adversarial_evasion.md`
- AWS↔Azure signal correspondence: `azure_symmetry.md`
- Per-path detection signature: `paths.md`
- Related-work coverage: `../../methodology/related_work.md` §3
