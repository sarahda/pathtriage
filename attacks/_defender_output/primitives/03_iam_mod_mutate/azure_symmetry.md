# Primitive 03 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 03's detection concept is expressible in Azure. Confirms cross-cloud validity without duplicating W8 Azure-KQL implementation. **This primitive has the strongest AWS↔Azure asymmetry finding in the catalogue** (D-Z4-02), documented in detail below.

## Signal Correspondence

The AWS primitive detects: **policy version creation + set-as-default correlation with elevated content vs prior version, correlated with prior attachment or subsequent use by the caller**.

The Azure equivalent detects (structurally): **role definition modification with expanded action list vs prior version, correlated with the caller's use of the modified role**.

Cloud-invariant primitive structure:
Policy/role mutation event
→ observed in control-plane logs
→ compared against prior policy/role content
→ correlated with caller's attachment/assignment history
→ fires on elevation-of-actions with matching before/after diff

## Azure paths covered

- **Z4** — Custom role definition abuse via `Microsoft.Authorization/roleDefinitions/write`

Single path in the primitive, but the finding it produces (D-Z4-02) is the most significant comparative asymmetry in the module.

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent |
|---|---|
| `eventName = CreatePolicyVersion` | `Microsoft.Authorization/roleDefinitions/write` (PUT) |
| `eventName = SetDefaultPolicyVersion` | (Not applicable — Azure has no version history model; role definitions are mutated in-place with implicit "current version" only) |
| `requestParameters.policyArn` | `properties.roleName` + resource ID of the roleDefinition |
| `requestParameters.policyDocument` (new content) | Request body `properties.permissions.actions[]` — the mutated action list |
| Prior version fetched via `GetPolicyVersion` | Prior state must be reconstructed from Activity Log's historical `roleDefinitions/write` events (Azure does not preserve immutable version history) |
| Correlation with caller's attachment history | Correlation with the calling principal's role assignments on that role |

## Asymmetries

### Asymmetry 1 — Azure has no policy version history ⭐

**AWS iam:CreatePolicyVersion** creates a NEW version that lives alongside old versions. Old versions remain accessible for rollback and forensic comparison. Detection can fetch the immediately-prior version from IAM directly and compute a diff — the "elevated content vs prior" signal is straightforward.

**Azure roleDefinitions/write** mutates the role in-place. Previous state is not preserved in Azure Resource Manager. Detection queries must reconstruct the prior state from Activity Log's historical events — expensive query, and older mutations may age out of retention.

**Detection implication**: Azure detection queries for primitive 03 are strictly more expensive than AWS. They must join current-state (from ARM API) against historical Activity Log events to reconstruct prior state. This affects query performance and log retention requirements.

### Asymmetry 2 — Azure has service-side privilege-escalation guard (D-Z4-02) ⭐⭐

**This is the primary primitive-03 comparative finding.** Documented in detail as D-Z4-02.

The finding: Azure RBAC enforces an **undocumented** service-side privilege-escalation guard on `roleDefinitions/write`. A principal cannot inject actions into a role definition that the principal does not itself already hold, regardless of whether they hold the `roleDefinitions/write` action.

Evidence: two-run experimental comparison with identical infrastructure. When calling principal is `User Access Administrator` (which holds `Microsoft.Authorization/*/write` but not the wildcard `*`), the mutation succeeds silently at PUT with HTTP 200 OK, but a follow-up GET five seconds later shows the mutation has been reverted. Attacker's downstream use of the "mutated" role fails with 403. When calling principal is `Owner` (which holds `*`), the mutation persists and downstream use succeeds.

**Structural consequence**: Azure structurally prevents privilege escalation via mutate primitive for principals below Owner scope. AWS provides no equivalent guard on `iam:CreatePolicyVersion` — any principal with that action can inject any actions. So:

- **AWS provides only reactive detection** for the mutate primitive.
- **Azure provides structural prevention on top of detection** for principals below Owner.

**Detection implication**: Azure primitive 03 detection is materially less critical than AWS primitive 03 detection. Azure's built-in guard eliminates a whole class of attackers (UAA-scoped principals). Detection is still needed for Owner-scoped principals, but the attacker surface is narrower.

**Verification note**: this finding was made experimentally during Z4 lab construction, not from Microsoft documentation. It is not documented in Microsoft Learn, MSRC blog, SpecterOps writeups, NetSPI research, or public GitHub searches. It is inferable via experimental verification (reproducible in five minutes) but not stated in any reference. Documented as an experimentally-observed, undocumented Azure RBAC behavior.

**Impact on catalogue framing**: Z4 must model the calling principal as Owner to be verifiable at all. This narrows the realistic attacker surface for Z4 compared to AWS P3 (any principal with `iam:CreatePolicyVersion`). Documented explicitly in Z4 README.

### Asymmetry 3 — Azure MI tokens don't reflect post-mutation permissions (D-Z4-03)

Azure MI tokens carry permission claims at issuance time. If a role is mutated via `roleDefinitions/write` after a token is issued, the change does not propagate to that in-flight token — a fresh IMDS token acquisition is required to see the new permissions.

AWS STS credentials propagate IAM changes near-immediately (typically <30 seconds). An in-flight STS credential set will start reflecting the new permissions without re-authentication.

**Detection implication**: Azure primitive 03 has a specific signature — the same-MI sequence `roleDefinitions/write` → fresh IMDS token acquisition → subsequent write via mutated role. All three events are visible in Activity Log; the correlation is high-confidence. This detection signal has no direct AWS analogue because AWS doesn't require the token refresh step.

### Asymmetry 4 — Elevation-target specificity

AWS `iam:CreatePolicyVersion` allows arbitrary policy content — attackers can inject any actions, any resources, any conditions. The mutated policy is fully attacker-controlled.

Azure `roleDefinitions/write` mutates a specific existing role definition. The attacker can only inject actions that would extend the role's scope. The mutation is constrained by the role's assignable scopes and by D-Z4-02's guard.

**Detection implication**: Azure detection can compare the mutated role against a fixed set of well-known "safe" custom role patterns. AWS detection has a broader search space — any policy document is possible content.

### Asymmetry 5 — Preventive control availability

AWS has SCP-based preventive controls: deny `iam:CreatePolicyVersion` on admin-equivalent policies, tag-based restrictions, etc. These are user-configurable SCPs.

Azure has D-Z4-02's built-in guard (below-Owner cannot inject actions they don't hold), plus role-based access control on `roleDefinitions/write` itself. Custom-deny policies via Azure Policy exist but are less expressive than AWS SCPs at the identity level.

**Detection implication**: Azure preventive-control layer is stronger by default (D-Z4-02), but user-configurable preventive controls are weaker than AWS SCPs. Overall balance: Azure primitive 03 has stronger built-in prevention but weaker custom prevention; AWS has weaker built-in prevention but stronger custom prevention.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 03 will:

1. Reference Azure Activity Log for `roleDefinitions/write` events (the mutation events themselves).
2. Reconstruct prior state via historical Activity Log query — expensive but necessary given Azure's lack of version history.
3. Compare pre-mutation and post-mutation action lists — flag any elevation-of-actions.
4. Correlate the mutation event with the calling principal's role assignments on that role (does the mutator hold or benefit from the mutation?).
5. **Include D-Z4-02 preflight**: check whether the calling principal already holds the injected actions. If they do (Owner-scoped), fire high-confidence. If they don't (UAA-scoped), the mutation would be reverted by Azure's guard — fire as informational only (still logged, but not alertable).
6. Include the D-Z4-03 signature — sequence of mutate → fresh IMDS → subsequent write via mutated role. This is the highest-confidence variant.

Primitive 03's design is validated as **cloud-invariant in structure but with strongly asymmetric prevention**. The AWS and Azure detection queries have similar shape (mutation + baseline diff + caller history). But the preventive-control layer differs materially, which affects the primitive's real-world value. AWS defenders must rely primarily on detection; Azure defenders benefit from Azure's built-in guard for below-Owner attackers.

The D-Z4-02 finding is the primary primitive-03 contribution to thesis Section 4 comparative analysis. It represents a case where Azure provides structural prevention that AWS delegates to reactive detection — a specific, actionable multi-cloud IAM design insight, not a general "AWS and Azure differ" statement.

## Coverage matrix (updated for verified paths)

| Path | Attacker requirement | Detection value | Preventive layer |
|---|---|---|---|
| P3 (AWS) | `iam:CreatePolicyVersion` on any admin-equivalent policy | High — attacker fully controls policy content | User-configurable SCPs only |
| Z4 (Azure) | `roleDefinitions/write` **AND** already-Owner scope (per D-Z4-02) | Lower — Azure's guard filters below-Owner attackers automatically | Built-in D-Z4-02 guard + user-configurable Azure Policy |

Coverage asymmetry: The Z4 attacker surface is narrower than P3 due to Azure's structural guard. Detection is therefore less critical on Azure but still needed for Owner-scoped compromise. This is the clearest example in the catalogue of a case where Azure's identity platform design provides defense-in-depth that AWS delegates to reactive detection.
