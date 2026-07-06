# Primitive 03 — Per-Path Signature Details

## P3 — CreatePolicyVersion Escalation

**Attack summary**: attacker has a low-privileged IAM user with `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` on a customer-managed policy that is already attached to the user (self-attach variant established in T1 W2 D-W2-01). Attacker calls `CreatePolicyVersion` with a wildcard policy document, then `SetDefaultPolicyVersion` to activate the new version. Because the policy is already attached, the attacker's permissions expand retroactively without any `AttachUserPolicy` event.

**Signature on this primitive**:

- Event 1: `CreatePolicyVersion` with policyArn = customer-managed policy, policyDocument containing `"Action": "*"` (or equivalent wildcard)
- Event 2 (within 5 minutes): `SetDefaultPolicyVersion` with the same policyArn and the new versionId. **Or**: setAsDefault=true on event 1 combines both events.
- Caller (`userIdentity.arn`) holds the policy attached (per prior `AttachUserPolicy` event) → caller_holds_policy: TRUE
- New version has admin action; prior version did not → new_has_admin_action: TRUE, prior_lacked_admin_action: TRUE
- Fire reason: `self_benefit_admin_injection`
- Confidence: **high**

**Baseline join contribution**: essential. Without the prior-version comparison, the primitive would fire on every `CreatePolicyVersion` where the new version has wildcards — including legitimate cases (initial admin policy creation). The delta requirement (`prior_lacked_admin_action`) restricts fires to genuine elevations.

**MTTD expectation**: seconds. Fire occurs on the `SetDefaultPolicyVersion` event (or on `CreatePolicyVersion` if setAsDefault=true), which is the attacker's second (or only) API call.

**Comparison-tool coverage**:

- **Cloudsplaining**: **partial** — flags policies that allow `iam:CreatePolicyVersion` as high-risk permissions in the caller's policy. Catches the misconfiguration before the attack, but does not observe the attack itself. Does not have a version-delta capability.
- **Prowler**: **miss** — audit rules do not include CreatePolicyVersion abuse patterns.
- **Datadog CloudSIEM**: **partial** — has a rule for `CreatePolicyVersion` events but treats all such events the same (does not diff against prior versions). Fires on every CreatePolicyVersion regardless of content, generating high FP on legitimate ops. In practice this rule is often disabled after tuning.
- **Sigma HQ cloud**: **miss** — no rule for this pattern.
- **CIS AWS Foundations v3.0**: **miss** — no preventive control for policy mutation.

## Coverage Matrix Row

For inclusion in `methodology/related_work.md` §3:

| Path | Cloudsplaining | Prowler | Datadog | Sigma | CIS | PathTriage primitive |
|---|---|---|---|---|---|---|
| P3 | partial | miss | partial | miss | miss | **03** |

Structural gap: **P3 is missed by 3 of 5 comparison tools**, and the two `partial` tools miss the version-delta signal that is the essence of the attack. This is one of the "at least one path missed by all commercial baselines" contributions cited in `evaluation_protocol.md` §6.

The specific gap: **no comparison tool computes a per-version content diff for CreatePolicyVersion events**. The primitive's `prior_versions` CTE and delta computation are the novel component. Datadog's undifferentiated rule illustrates the alternative — high recall but unusable precision.

## Mutate primitive vs Assign primitive — cross-primitive context

Primitive 02 (assign) covers P5 (`iam:AttachUserPolicy`). The two primitives together cover the IAM-modification class:

- **Assign**: creates a new attachment record. Visible in `iam:ListAttachedUserPolicies` audits. Detected by primitive 02.
- **Mutate**: modifies an existing attachment's underlying policy. **Invisible** to attachment audits. Detected by primitive 03.

A defender relying on `ListAttachedUserPolicies`-style audits will detect P5 (assign) but silently miss P3 (mutate). The victim principal's attached policies list appears unchanged; only the policy's content has changed. This is precisely why the mutate primitive is a separate detection signal, and why the "convergence to a single IAM-modification primitive" claim in the midway report was refined during Z4 verification.

The Azure equivalents (Z3 assign, Z4 mutate) exhibit the same structural distinction with an added service-side asymmetry: Azure's privilege-escalation guard blocks caller-exceeding mutations, while AWS does not. See `azure_symmetry.md`.
