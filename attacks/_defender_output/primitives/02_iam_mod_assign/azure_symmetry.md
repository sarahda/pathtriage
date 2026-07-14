# Primitive 02 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 02's detection concept is expressible in Azure. Confirms cross-cloud validity without duplicating W8 Azure-KQL implementation.

## Signal Correspondence

The AWS primitive detects: **self-attach of a policy or attach of a policy where the caller-target-policy 3-tuple has no history**.

The Azure equivalent detects: **role assignment creation where the caller-recipient-role 3-tuple has no history**.

Cloud-invariant primitive structure:
Policy/role assignment event
→ observed in control-plane logs (CloudTrail Attach*/Put* / Azure roleAssignments/write)
→ correlated with baseline history (caller × target × grant)
→ fires when self-attach with admin-equivalent grant OR
caller-target-policy 3-tuple is novel OR
target's post-grant permission is admin-equivalent

## Azure paths covered

Two Azure paths exercise this primitive with related but distinct mechanics:

- **Z3** — Managed Identity with User Access Administrator self-elevates by creating a role assignment binding itself to Owner at RG scope. **Single identity, single hop, self-target.**
- **Z7** — Related but distinct: SP-A with UAA grants Contributor to SP-B (attacker-controlled but distinct identity). **Two identities, cascade grant.** Covered by primitive 05 (trust topology), not this primitive — the detection signature differs (`principalId != caller`).

Z3 is the pure assign primitive: caller and target are the same identity. Z7 exercises the same underlying action (`roleAssignments/write`) but under a different detection primitive because the caller-recipient mismatch is the defining feature.

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent |
|---|---|
| `eventName = AttachUserPolicy` / `AttachRolePolicy` / `PutUserPolicy` | `Microsoft.Authorization/roleAssignments/write` |
| `userIdentity.arn` (caller) | Azure Activity Log `caller` field |
| `requestParameters.userName` (target) | Role assignment `principalId` |
| `requestParameters.policyArn` (attached policy) | Role assignment `roleDefinitionId` |
| CloudTrail `eventTime` | Azure Activity Log `eventTimestamp` |
| Historical join dimension: `(caller, target, policyArn)` 3-tuple | Historical join dimension: `(caller, principalId, roleDefinitionId)` 3-tuple |
| Admin-equivalent policy detection: known AWS-managed admin ARNs | Admin-equivalent role detection: known built-in role GUIDs (Owner, Contributor, User Access Administrator) |

## Asymmetries

### Asymmetry 1 — Built-in role GUIDs are stable across subscriptions

Azure built-in role definitions (Owner, Contributor, User Access Administrator, etc.) have stable GUIDs across every Azure subscription. This means an Azure detection primitive can hard-code admin-role IDs — e.g., `Owner` is always `8e3af657-a8ff-443c-a75c-2fe8c4bcb635`.

AWS relies on `AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess` policy ARNs, which are also stable. So the asymmetry is small but present: Azure has a slightly cleaner query (GUID equality vs policy-ARN string match).

**Detection implication**: Azure's primitive can use GUID equality checks; AWS needs policy-ARN string matches. Similar precision but different implementation.

### Asymmetry 2 — Scope granularity differs materially

AWS policies attach to identities (users, roles, groups) — the "scope" is the identity itself. To limit blast radius, the policy content must include resource-level constraints.

Azure role assignments have three orthogonal dimensions: **principalId** (identity), **roleDefinitionId** (role), and **scope** (management group / subscription / RG / individual resource). The same role can be assigned at subscription vs RG scope with drastically different blast radius.

**Detection implication**: Azure primitive 02 must include scope analysis in the query. A Contributor assignment at RG scope (`/subscriptions/x/resourceGroups/y`) is materially less dangerous than at subscription scope (`/subscriptions/x`). Baseline-anomaly signals should weight by scope breadth — a wider scope assignment is a stronger signal than a narrower one. This dimension has no AWS equivalent.

### Asymmetry 3 — Assignment scoping vs policy content

AWS gives attackers two abusable primitives: (a) attach an existing admin-equivalent policy, or (b) create a new inline policy with admin actions (via `PutUserPolicy`). Both surface in CloudTrail as distinct event types.

Azure gives attackers primarily one primitive: assign an existing role. Creating a *new* custom role is a distinct event (`Microsoft.Authorization/roleDefinitions/write` — covered by primitive 03 mutate) and requires separate high-privilege actions.

**Detection implication**: AWS primitive 02 must handle both `AttachUserPolicy` and `PutUserPolicy` (inline creation) — two event types. Azure primitive 02 handles only `roleAssignments/write` — one event type. Simpler on Azure at this level, but Azure also has to distinguish Z3 (self-elevation via existing role) from Z7 (cascade via existing role) via principalId analysis, which AWS doesn't require at this primitive.

### Asymmetry 4 — Detection signature by principal comparison

Z3's defining signature: `principalId == caller`. This is a **self-assign**, the direct AWS analogue of `AttachUserPolicy` where `targetUser == caller`.

Z7's defining signature: `principalId != caller`. This is a **cascade grant** to a distinct identity — covered by primitive 05 (trust topology).

**Detection implication**: primitive 02's Azure query MUST include the `principalId == caller` filter to correctly separate Z3-style attacks from Z7-style cascades. Without this filter, Z3 and Z7 fire on the same query, obscuring the two distinct attack patterns. AWS doesn't have this concern at primitive 02 because attach-policy semantics don't naturally cascade the same way.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 02 will:

1. Reference Azure Activity Log as the primary event source (`Microsoft.Authorization/roleAssignments/write` events).
2. Filter on `principalId == caller` to isolate self-assigns (Z3-style), leaving cascade patterns (Z7-style) to primitive 05.
3. Include scope-breadth analysis — a subscription-scope Owner assignment is a stronger signal than an RG-scope Owner assignment.
4. Use hard-coded built-in role GUIDs for admin-equivalent detection (Owner, Contributor, User Access Administrator).
5. Include baseline join on `(caller, roleDefinitionId, scope)` 3-tuple for anomaly detection — never-before-seen combinations are the primary signal.
6. Cross-reference primitive 05 for related cascade attacks — the two primitives together cover all `roleAssignments/write` patterns in the catalogue.

Primitive 02's design is validated as **structurally cloud-invariant**. The AWS and Azure queries have the same shape (event + baseline join + admin detection). Only the specific field names and role identifier formats differ.

## Coverage matrix (updated for verified paths)

| Path | Detection signature | Baseline join dimension | Primary signal |
|---|---|---|---|
| P5 (AWS) | `AttachUserPolicy` where target == caller AND policyArn is admin-equivalent | `(caller, target, policyArn)` novelty | Self-attach + admin policy |
| Z3 (Azure) | `roleAssignments/write` where `principalId == caller` AND `roleDefinitionId` is admin-equivalent | `(caller, principalId, roleDefinitionId, scope)` novelty | Self-assign + admin role |

Coverage symmetry: AWS P5 and Azure Z3 exercise the same primitive with nearly identical detection structure. Only scope-breadth analysis is Azure-specific.

Related coverage handled by primitive 05:

| Path | Reason for primitive 05 assignment |
|---|---|
| P4 (AWS) | Chain-based delegation; not self-attach — different signature (session-level chain) |
| Z7 (Azure) | Cascade grant to distinct identity; `principalId != caller` — different signature (authorization-level cascade) |
