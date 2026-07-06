# Primitive 02 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 02's detection concept is expressible in Azure. Confirms cross-cloud validity without duplicating W8 Azure-KQL implementation.

## Signal Correspondence

The AWS primitive detects: **IAM policy assignment where a caller binds an existing (or new inline) policy to a principal that gains previously-absent elevated authority**.

The Azure equivalent detects: **role assignment (`Microsoft.Authorization/roleAssignments/write`) where a caller binds an existing role definition to a principal that previously did not hold equivalent scope**.

Cloud-invariant primitive structure:

```
Policy/role assignment event
    → caller performs the assignment
    → target is bound to the policy/role
    → observed in control-plane logs (CloudTrail / Activity Log)
    → correlated with:
        - self-attach flag (caller == target)
        - caller-history baseline (has caller ever granted this before)
        - target-history baseline (has target ever held equivalent scope)
    → fires on any of the three conditions
```

## Azure paths covered

- **Z3** — Role assignment manipulation (`roleAssignments/write` → self-Owner via UAA). Direct analogue of P5.

Not covered: Z4 (which uses `roleDefinitions/write` — mutate primitive, covered by primitive 03).

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent | Notes |
|---|---|---|
| CloudTrail `eventName = AttachUserPolicy` | AzureActivity `OperationName = Microsoft.Authorization/roleAssignments/write` | Direct equivalent event |
| CloudTrail `userIdentity.arn` (caller) | AzureActivity `Caller` (principal object ID) | Same semantic |
| CloudTrail `requestParameters.userName` (target) | AzureActivity request body `properties.principalId` | Target of the assignment |
| CloudTrail `requestParameters.policyArn` | AzureActivity request body `properties.roleDefinitionId` | Role being assigned |
| Historical policy attachments (from CloudTrail) | Historical role assignments (from AzureActivity) | Both surfaces support baseline join over the same event stream |
| AWS admin-equivalent policy list (fixed) | Azure Owner/Contributor/User Access Administrator (fixed) | Direct equivalents |

The mapping is one-to-one. Primitive 02's Azure counterpart in W8 uses AzureActivity with the same three-baseline-join structure.

## Asymmetries

### Asymmetry 1 — Assignment scope vs identity-based grants

AWS IAM policy attachment is identity-centric: a policy is attached to a specific user, role, or group. The target is unambiguous.

Azure role assignments are scoped: a role assignment binds a principal to a specific scope (management group / subscription / resource group / resource). The same principal + role can be assigned at multiple scopes. Detection must consider not just the target principal but also the target scope.

**Detection implication**: the Azure counterpart of primitive 02 needs an additional dimension in the baseline join — historical scope for the target principal. A principal who previously had Contributor at RG scope and now gets Contributor at subscription scope is a scope-escalation event that has no direct AWS analogue.

### Asymmetry 2 — Self-attach semantics differ across identity types

AWS `iam:UserName` condition variable matches for IAM users but not for federated identities or assumed-role sessions. Self-attach detection requires the caller and target to both be IAM users (or a heuristic ARN suffix match for roles).

Azure principals uniformly have object IDs regardless of type (user, group, service principal, managed identity). Self-attach detection is a direct object-ID comparison, no type-specific handling required. Azure's detection is structurally cleaner.

**Detection implication**: Azure counterpart of primitive 02 has a simpler self-attach check. AWS detection has a heuristic component (documented in `cloudtrail_lake_query.sql` Step 5).

### Asymmetry 3 — Prevention model

AWS provides preventive SCPs (see `scp_snippet.json`) that can deny IAM assign actions organisation-wide with conditions.

Azure provides Azure Policy and Conditional Access, but neither has a direct equivalent of "deny role assignment where caller matches target." Azure's preventive story for the assign primitive is weaker; runtime detection carries more weight.

**Detection implication**: no immediate detection-quality impact, but relevant to the module's overall coverage claim — AWS's preventive layer eliminates some of the fire cases that Azure detection must catch.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 02 will:

1. Reuse the three-baseline structure (self-attach, caller-history, target-scope-history).
2. Extend target-history baseline with a scope dimension (RG → sub escalation is a distinct anomaly class).
3. Use object-ID equality for self-attach (no heuristic ARN matching required).
4. Document the weaker preventive story and rely on detection more heavily than AWS.

Primitive 02's design is validated as cloud-invariant modulo the three asymmetries above.
