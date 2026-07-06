# Primitive 03 — IAM Modification (Mutate)

## Coverage

This primitive covers one verified AWS attack path:

| Path | Attack | Mutate action |
|---|---|---|
| P3 | CreatePolicyVersion Escalation | Attacker calls `iam:CreatePolicyVersion` to create a new version of a customer-managed policy with elevated actions, then `iam:SetDefaultPolicyVersion` to activate it. All principals with the policy attached are retroactively elevated. |

## Why this primitive is separate from Primitive 02 (assign)

The AWS IAM-modification class was collapsed to a single primitive in the midway report. During Z4 verification (`attacks/Z4_custom_role_definition_abuse/README.md` D-Z4-02), a structural asymmetry between AWS and Azure was surfaced that only manifests when assign and mutate are treated as distinct primitives:

- **AWS treats both primitives symmetrically**: any principal with `iam:CreatePolicyVersion` on a policy can inject any actions into that policy, regardless of whether the principal itself already holds those actions. Reactive detection only.
- **Azure treats them asymmetrically**: the mutate primitive (`roleDefinitions/write`) is subject to an undocumented privilege-escalation guard that silently reverts mutations exceeding the caller's own permissions. Only Owner (holding `*`) can inject `*` into a role definition; UAA (holding `Microsoft.Authorization/*/write` but not `*`) cannot, despite advertising the required action.

This is a structural difference in privilege models. Treating assign and mutate as one primitive erases the difference. Primitive 02 (assign) and primitive 03 (mutate) preserve it.

The convergence refinement (midway 8→4 → refined 8→5) is driven entirely by this split. Documented in the root `README.md` §Detection Primitives and in `attacks/_defender_output/README.md`.

## Detection Rationale

Legitimate `iam:CreatePolicyVersion` is uncommon but not zero. Customer-managed policies are edited when access requirements change; version rollover is the standard mechanism. Attack detection cannot be based on the event's existence alone.

The attack signature is a **policy-content-delta anomaly**: the new policy version grants actions the previous default version did not grant, AND the mutation is either self-benefiting (the caller holds the mutated policy) or scope-escalating (the new version's action set is admin-equivalent).

The primitive treats `CreatePolicyVersion` and `SetDefaultPolicyVersion` as a **correlated pair**. A `CreatePolicyVersion` alone creates an inactive version; the elevation is not effective until `SetDefaultPolicyVersion` activates it. Attackers execute both back-to-back within seconds. Legitimate ops may separate the two events by minutes or hours (create → review → activate) or may use the `--set-as-default` flag on `CreatePolicyVersion` to combine them.

The baseline-join dimension is **policy-version-history**. For each `CreatePolicyVersion` event:

- **Extract** the new version's actions from `requestParameters.policyDocument`.
- **Compute delta** against the current default version's actions (fetched from prior CloudTrail events for the same policy or from the account's IAM state).
- **Score** the delta against admin-equivalence rules and against the policy's attached-principals.

The primitive fires when: delta contains new admin-equivalent actions AND (subsequent `SetDefaultPolicyVersion` within short window OR `setAsDefault=true` in the create call).

## Baseline-Join Approach

Query joins the candidate event against three historical anchors:

1. **Prior policy version content**: what actions did the policy's current default version include? Fetched from prior `CreatePolicyVersion` events (or from the initial `CreatePolicy` event for v1). Used to compute the delta.
2. **Policy attachment count**: how many principals currently hold this policy attached? A mutation on a policy attached to many principals is a mass-elevation event even if no single principal is admin-elevated by design.
3. **Caller's own scope**: does the caller currently hold the policy attached? Self-benefiting mutations are the highest-confidence signal.

## Query Semantics

See `cloudtrail_lake_query.sql`. In prose:

```
For each CloudTrail event C in the last 24h where
    C.eventName = "CreatePolicyVersion"
    AND (
        C followed by SetDefaultPolicyVersion event S within 5 minutes,
        OR C.requestParameters.setAsDefault = true
    )

Extract:
    - caller: C.userIdentity.arn
    - policy: C.requestParameters.policyArn
    - new_actions: parse from C.requestParameters.policyDocument
    - old_actions: fetch from prior default version

If (new_actions - old_actions) contains admin-equivalent actions:
    → fire (elevation signal)

If caller has policy attached:
    → fire with confidence 'high' (self-benefit)

If policy is attached to > threshold principals:
    → fire with confidence 'medium' (mass elevation)
```

## Coverage per Path

See `paths.md`. Summary:

- **P3**: attacker calls `CreatePolicyVersion` with a wildcard policy document, then `SetDefaultPolicyVersion`. Fires with `high` confidence because the caller has the policy attached (self-benefit). MTTD ≈ seconds (the two-event correlation window is 5 minutes; fire is on the second event).

## Preventive Control

`scp_snippet.json` denies `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` for non-authorized identities, using a tag-based positive control (`iam-policy-mgmt-authorized=true`).

**Important limitation**: no SCP can prevent the mutate primitive at the content level, because SCPs cannot inspect policy documents. An identity authorised to manage customer policies retains the ability to inject wildcards into any policy version. The preventive layer bounds *who* can mutate; the detection layer catches *what* is mutated. Detection is not optional.

## Structural asymmetry with Azure (thesis contribution)

The mutate primitive is where AWS and Azure diverge sharply. Documented in detail in `azure_symmetry.md`.

- **AWS**: any principal with `iam:CreatePolicyVersion` on a policy can inject arbitrary actions. No cloud-side privilege-escalation guard. Detection is reactive only.
- **Azure**: `roleDefinitions/write` is subject to a privilege-escalation guard (D-Z4-02). A principal cannot inject actions they do not themselves hold. `PUT` returns 200 OK but a backend validator reverts within seconds. Detection can leverage this by comparing the persisted state against the request body.

The asymmetry is a material contribution to thesis §4 (Comparative Analysis).

## Evaluation Summary

Populated after Phase 4 execution. See `evaluation.md`.

## References

- Adversarial evasion: `adversarial_evasion.md`
- AWS↔Azure signal correspondence (with D-Z4-02 detail): `azure_symmetry.md`
- Per-path detection signature: `paths.md`
- Related-work coverage: `../../methodology/related_work.md` §3
