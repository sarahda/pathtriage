# Primitive 03 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 03's detection concept is expressible in Azure, and document the **primary structural asymmetry** between AWS and Azure IAM: Azure enforces a service-side privilege-escalation guard on the mutate primitive that AWS does not have. This asymmetry is the material contribution of the Z4 verification (D-Z4-02) to the AWS-Azure comparative analysis in thesis §4.

## Signal Correspondence

The AWS primitive detects: **modification of an existing IAM policy where the new version grants actions the prior version did not, and the modification is activated**.

The Azure equivalent detects: **modification of an existing role definition where the new `actions[]` array grants actions the prior definition did not**.

Cloud-invariant primitive structure:

```
Policy/role-definition version modification event
    → caller writes a new version of an existing policy/role
    → observed in control-plane logs (CloudTrail / Activity Log)
    → correlated with prior version content (version-content baseline join)
    → fires on:
        - new admin actions present AND absent in prior
        - and (self-benefit OR mass-attachment OR persistent activation)
```

## Azure paths covered

- **Z4** — Custom role definition abuse: caller (Owner) injects `"*"` into a custom role's `actions[]`. Direct analogue of P3.

Not covered: Z3 (assign — covered by primitive 02).

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent | Notes |
|---|---|---|
| CloudTrail `eventName = CreatePolicyVersion` | AzureActivity `OperationName = Microsoft.Authorization/roleDefinitions/write` | Direct equivalent |
| CloudTrail `requestParameters.policyArn` | AzureActivity request body `properties.roleName` + resource ID | Role definition identity |
| CloudTrail `requestParameters.policyDocument` | AzureActivity request body `properties.permissions[0].actions` | The new content to be validated |
| Prior version fetched from earlier CloudTrail events | Prior version fetched from earlier AzureActivity events | Same baseline structure |
| CloudTrail `SetDefaultPolicyVersion` separate event | Azure combines create + activate in one operation | Simpler on Azure — no correlation-window logic needed |
| Attach relationship (from AttachPolicy events) | Role assignment relationship (from roleAssignments/write events) | Both surfaces support attachment-count baseline |

The mapping is one-to-one for the fields. The main structural simplification on Azure is that role definition mutation is atomic — no separate "activate" event is needed, since the write immediately becomes effective (subject to the privilege-escalation guard, below). Azure's counterpart of primitive 03 does not need the `activated_creates` CTE.

## THE ASYMMETRY: Azure's undocumented privilege-escalation guard

**AWS**: any principal with `iam:CreatePolicyVersion` can inject `"Action": "*"` into a policy. The IAM service does not check whether the calling principal itself has the actions being written. The mutation persists. This is verifiable — see attack P3's verification log for a low-privileged user mutating a customer policy to grant themselves `*`.

**Azure**: Azure RBAC enforces a service-side privilege-escalation guard at the `Microsoft.Authorization` resource provider. A principal that does not already hold action A cannot inject A into any role definition's `actions[]`. The `PUT roleDefinitions/{id}` API call returns 200 OK with the echoed body, but a backend validator within seconds reverts the persisted state to the previous version. Verified experimentally during Z4 build (`attacks/Z4_custom_role_definition_abuse/README.md` D-Z4-02):

| Starting role | `PUT` HTTP code | `GET` after 5s | Downstream write via mutated role |
|---|---|---|---|
| `User Access Administrator` (holds `Microsoft.Authorization/*/write` but not `*`) | 200 OK | actions reverted to read-only | 403 AuthorizationFailed |
| `Owner` (holds `*`) | 200 OK | actions persist as `["*"]` | Succeeds |

This behaviour is **not documented in Microsoft's public RBAC reference**. It was discovered by experimental verification during Z4 catalogue build.

## Detection implications of the asymmetry

The Azure counterpart of primitive 03 gains a **verification signal** that the AWS primitive does not have:

- Azure fire condition: `roleDefinitions/write` succeeds AND a follow-up `GET` within 10 seconds shows the mutation persisted. If the mutation was silently reverted, no elevation occurred; the event is not an actionable fire.
- AWS has no such gate. Every syntactically-valid `CreatePolicyVersion` results in a persisted change; detection must fire on all of them and rely on downstream context for confidence.

The consequence: **the Azure primitive has structurally lower FP rate than the AWS primitive**. Fires that Azure silently blocks are not surfaced to the defender; the AWS defender sees them all.

## Comparative summary

| Dimension | AWS P3 | Azure Z4 |
|---|---|---|
| Cloud-side privilege-escalation prevention | None | Yes (D-Z4-02) |
| Required starting authority | Any principal with `iam:CreatePolicyVersion` on the policy | The caller must already hold the actions being written |
| Persistence semantics | Always persists | Persists only if guard passes |
| Detection role | Reactive only (fire on all) | Reactive + verification (fire only on persisted) |
| Effective attacker surface | Broad | Narrow (Owner-equivalent required) |
| Best defensive posture | Detection + preventive tag-based SCP (partial) | Detection is enough; guard closes the primitive for non-Owner attackers |

## Contribution to thesis §4

The asymmetry documented here is the **most concrete comparative-analysis contribution** in PathTriage. It is:

1. **Structural**, not implementation-specific — it reflects a design decision in Azure RBAC that has been in place since at least 2020.
2. **Undocumented** in Microsoft's public references — the guard's existence is inferable from experimental behaviour but not stated.
3. **Materially affects the detection story** — Azure's primitive has strictly lower FP rate on this attack class.
4. **Verifiable end-to-end** — the Z4 attack lab includes the two-run comparison (UAA vs Owner) in `verification_log.txt`.

For thesis §4, the argument is: "AWS and Azure have converged on similar named actions (`iam:CreatePolicyVersion` vs `Microsoft.Authorization/roleDefinitions/write`) with similar-looking privilege primitives. But Azure has added a service-side guard AWS does not have, materially changing the detection story. This structural difference is undocumented but experimentally verifiable, and it is the kind of asymmetry that a purely permission-model analysis (e.g., IAM policy simulator, Azure Policy analysis) would miss."

The contribution is not a criticism of AWS or an endorsement of Azure — both approaches are defensible design choices. The contribution is naming the asymmetry and quantifying its detection implication.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 03 will:

1. Reuse the version-delta baseline structure.
2. Add a **post-write verification** step: after `roleDefinitions/write` succeeds, wait 10s and GET the role definition. Compare the persisted content against the request body. Only fire if the mutation persisted.
3. Note in operator documentation that Azure's guard eliminates a large class of naive fires; alert routing can be more aggressive than on AWS.
4. Document D-Z4-02 in the Azure primitive's `README.md` (post-W8) as the primary detection-quality difference from the AWS primitive.

Primitive 03's design is validated as cloud-invariant in structure, but the asymmetry in the underlying privilege model is material and is the primary contribution point for thesis §4.
