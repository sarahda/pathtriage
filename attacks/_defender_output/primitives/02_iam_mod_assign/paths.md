# Primitive 02 — Per-Path Signature Details

## P5 — AttachPolicy Escalation

**Attack summary**: attacker has a low-privileged IAM user with the specific permission `iam:AttachUserPolicy` scoped to their own user ARN (a common misconfiguration in customer-managed policies granting "self-service"). Attacker calls `AttachUserPolicy` with policyArn = `AdministratorAccess`, target = own username. Post-attack, they hold full administrative access.

**Signature on this primitive**:

- Event: `AttachUserPolicy`
- Caller (`userIdentity.arn`) matches target (`requestParameters.userName`) → self-attach flag: **TRUE**
- Policy ARN is `arn:aws:iam::aws:policy/AdministratorAccess` → admin-equivalent flag: **TRUE**
- Fire reason: `self_attach_admin`
- Confidence: **high**

**Baseline join contribution**: none required for high-confidence fire; self-attach + admin policy is definitive without historical context. Baseline join is used for the medium-confidence fires (unestablished caller, target elevation).

**MTTD expectation**: seconds — the attach itself is the fire event.

**Comparison-tool coverage**:

- **Cloudsplaining**: **detect** — flags `iam:AttachUserPolicy` scoped to the caller's own ARN as a privilege-escalation pattern in the caller's policy. Catches at policy-review time, before the attack.
- **Prowler**: **partial** — audit checks for overly-permissive policies but does not correlate self-attach at runtime.
- **Datadog CloudSIEM**: **detect** — rule `AWS User Attached to Admin Policy` fires. Does not require self-attach; also fires on legitimate admin assignment.
- **Sigma HQ cloud**: **partial** — has an `AttachUserPolicy` rule but without the self-attach condition, so it fires on all admin assignments (high FP rate on legitimate ops).
- **CIS AWS Foundations v3.0**: **partial** — Control 1.8 (root user access key rotation) and 1.10 (MFA on privileged users) are preventive against related patterns; no direct preventive control for self-attach.

## Coverage Matrix Row

For inclusion in `methodology/related_work.md` §3:

| Path | Cloudsplaining | Prowler | Datadog | Sigma | CIS | PathTriage primitive |
|---|---|---|---|---|---|---|
| P5 | detect | partial | detect | partial | partial | **02** |

Structural gap: 3 of 5 tools have `partial` coverage — they detect broad IAM assignment activity but do not distinguish self-attach or scope-escalation from legitimate ops. Cloudsplaining catches it at policy-static-analysis time; Datadog catches it at runtime but with high FP rate on ops teams.

PathTriage primitive 02 combines the self-attach detection (Cloudsplaining's contribution, moved to runtime) with the scope-escalation baseline join (novel — no comparison tool expresses this). Confidence-tiered output (`high` / `medium`) permits FP-tolerant deployment.

## Assign primitive vs Mutate primitive — cross-path context

Primitive 03 (mutate) covers P3 (CreatePolicyVersion). The AWS analogue relationship to Azure:

- P5 (assign) ↔ Z3 (`roleAssignments/write`): both bind an existing policy/role to a new principal. Both are visible in assignment audits.
- P3 (mutate) ↔ Z4 (`roleDefinitions/write`): both rewrite the underlying policy/role definition. Both are invisible to assignment audits.

The two primitives together cover the IAM-modification class completely. The split was informed by the Z4 verification finding (`attacks/Z4_custom_role_definition_abuse/README.md` D-Z4-02) that Azure enforces a service-side privilege-escalation guard on the mutate primitive but not on the assign primitive — a structural asymmetry that only manifests when the two are treated as distinct primitives.
