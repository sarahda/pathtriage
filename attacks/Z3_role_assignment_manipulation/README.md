# Z3 — Role assignment manipulation (self-grant Owner via UAA)

## Overview

A VM with a System-Assigned **Managed Identity (MI)** holds the `User Access Administrator` role scoped to a single resource group — a plausible "delegated permission-management" misconfiguration where the operator wanted to let the VM rotate role assignments on the resources it owns. `User Access Administrator` (UAA) includes `Microsoft.Authorization/roleAssignments/write`, which is sufficient to **grant the MI any role at the same scope, including Owner**. The exploit performs that self-grant, then deletes the original UAA assignment, leaving the MI as Owner of the resource group with no trace of the privilege-escalation step in its own role-assignment history.

This is the Azure analogue of the AWS "self-attach" pattern (P5 — `iam:AttachUserPolicy` scoped to the user's own ARN). The catalogue lesson: **any role granting `roleAssignments/write` at any scope is effectively Owner at that scope**, regardless of what other actions the role does or does not include. UAA's narrow advertised purpose ("manage who can access this resource") obscures this equivalence.

## Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│  VM (System-Assigned MI)                                     │
│    RBAC: User Access Administrator on RG '<rg>'              │
│          (no other elevated roles)                           │
└────────┬─────────────────────────────────────────────────────┘
         │  ① IMDS  → ARM token (resource=management.azure.com)
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  GET .../roleAssignments?$filter=principalId eq self    │
│       inventory: 1 assignment (UAA on RG)                    │
└────────┬─────────────────────────────────────────────────────┘
         │  ② baseline RBAC inventory
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  PUT .../roleAssignments/<newGuid>                      │
│       principalId    = self (MI objectId)                    │
│       roleDefinition = Owner                                 │
│       requires: Microsoft.Authorization/roleAssignments/write│
└────────┬─────────────────────────────────────────────────────┘
         │  ③ self-grant Owner
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  GET .../roleAssignments?...   (re-inventory)           │
│       confirms: 2 assignments (UAA + Owner)                  │
└────────┬─────────────────────────────────────────────────────┘
         │  ④ verify
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  DELETE .../roleAssignments/<original UAA assignment>   │
│       Owner permits removal; Owner persists.                 │
└──────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

- **T1098** — Account Manipulation (modifying an identity's RBAC to maintain or escalate access)
- **T1078.004** — Valid Accounts: Cloud Accounts (the MI continues to operate as a valid identity post-escalation)
- AWS analogue: **P5 — AttachPolicy (self-attach variant)** — `iam:AttachUserPolicy` scoped to the user's own ARN

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure_personal/`)
- Personal MSA subscription (operator is sole AAD admin) — Z3 itself does not require AAD writes, but is hosted on the personal MSA for environmental consistency with Z2–Z8 (see D-Z2-01)
- `~/.ssh/id_rsa.pub` present
- `az` CLI logged in; `ARM_SUBSCRIPTION_ID` / `ARM_TENANT_ID` exported
- Operator must be `Owner` or `User Access Administrator` at RG scope to assign UAA to the VM MI (Terraform performs this assignment at apply-time)

## Vulnerable Configuration

The Z3 scenario provisions exactly one over-broad grant:

- VM System-Assigned MI is given `User Access Administrator` on `baseline_azure_personal`'s RG.
- The MI holds no other elevated roles. Without `roleAssignments/write`, this configuration would already be lateral-movement-bait — *with* it, it is a one-step self-promotion to Owner.

There is no separate "victim" identity in Z3: the attacker (MI) and the target of escalation (also MI) are the same principal. The misconfiguration is purely the **role assignment**, not the identity layout.

## Why `User Access Administrator` Is Effectively Owner

`User Access Administrator` is documented as scoped to managing user access. In practice, it has only two actions of interest:

```
Microsoft.Authorization/*/read
Microsoft.Authorization/*/write
Microsoft.Authorization/*/delete
```

The `*/write` covers `roleAssignments/write`. Once an identity can write a role assignment at a scope, it can choose **any** role definition (Owner, Contributor, Custom, …) and **any** principal (including itself). UAA's narrow naming creates a perception that it is safer than Contributor or Owner; in reality, it is **strictly more dangerous than Contributor** (UAA → Owner is one PUT; Contributor → Owner is impossible without UAA or Owner) and **equal in power to Owner** at the same scope.

The same equivalence holds for any custom role that includes `Microsoft.Authorization/roleAssignments/write`.

## Attack Steps

1. From the workstation, establish SSH access to the VM as `azureuser`.
2. From inside the VM, query IMDS for an ARM-scoped Bearer token (MI auth).
3. List role assignments held by the MI's principal at RG scope (baseline inventory: UAA only).
4. Generate a fresh GUID and `PUT .../roleAssignments/<guid>` with `principalId=self` and `roleDefinitionId=Owner`.
5. Re-list role assignments at the same scope (now: UAA + Owner).
6. (Optional, destructive) `DELETE` the original UAA assignment as the new Owner — proves Owner is sufficient for RBAC writes/removals and demonstrates trace-removal.

## Running the PoC

From the project root:

```bash
# 0. context
az account show --query name -o tsv     # personal MSA, not UNSW
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export ARM_TENANT_ID=$(az account show --query tenantId -o tsv)

# 1. deploy
cd environments/scenarios/Z3_role_assignment_manipulation
terraform init && terraform apply -auto-approve
sleep 30                                # IAM propagation

# 2. ship exploit
terraform output -json > /tmp/z3_output.json
VM_IP=$(jq -r '.vm_public_ip.value' /tmp/z3_output.json)
scp ../../../attacks/Z3_role_assignment_manipulation/exploit.py \
    /tmp/z3_output.json azureuser@$VM_IP:~/

# 3. execute
ssh azureuser@$VM_IP 'cloud-init status --wait && \
    python3 exploit.py --tf-output z3_output.json --log verification_log.txt'

# 4. retrieve log
scp azureuser@$VM_IP:~/verification_log.txt \
    ../../../attacks/Z3_role_assignment_manipulation/verification_log.txt
```

Add `--skip-revoke` to step 3 if you want the original UAA assignment preserved (cleaner `terraform destroy` afterwards).

## Captured Output (PoC Verification)

The full sanitized PoC log is committed to this directory as `verification_log.txt`. The raw log (containing actual subscription, tenant, MI principal, and assignment GUIDs) is retained outside the repository.

See `verification_log.txt` for the full step-by-step trace. The exploit produces a final verification line of the form:

```
[+] Path Z3 verified: VM MI (User Access Administrator on RG) ->
                      self PUT roleAssignments ->
                      Owner on RG (RBAC modification persistent)
```

## Comparison to AWS Analogue

| Dimension | AWS P5 (AttachPolicy self-attach) | Azure Z3 (UAA self-grant Owner) |
|---|---|---|
| Required action | `iam:AttachUserPolicy` scoped to self ARN | `Microsoft.Authorization/roleAssignments/write` at scope |
| Granting role | A managed/inline policy with the above | `User Access Administrator` (built-in) |
| Escalation primitive | Attach `AdministratorAccess` policy to self | PUT a roleAssignment binding Owner to self |
| Persistence after pivot | New policy attachment in IAM history | New roleAssignment GUID under the scope |
| Cleanup of trace | Detach the *original* policy as new admin | DELETE the original UAA assignment as new Owner |
| Symmetry | "iam:AttachUserPolicy can grant anything" | "roleAssignments/write can grant anything" |
| Naming trap | Policy name `AttachOnly` sounds safe | Role name `User Access Administrator` sounds scoped |

The structural equivalence is exact: in both clouds, **any permission to write authorization records is equivalent to full administrative authority at the same scope**. PathTriage rubric treats them as the same primitive (IAM modification class) for detection-template purposes.

## Detection Preview (full rules in W8 defender-output module)

| Signal | Source | Primitive |
|---|---|---|
| `roleAssignments/write` by a principal whose target principalId equals the caller's MI/SP objectId | `AzureActivity` | Self-grant pattern: `properties.principalId == caller.objectId` |
| New roleAssignment binds Owner / Contributor / UAA where the caller's prior history is read-only | `AzureActivity` | Behavioural baseline anomaly on the caller |
| `roleAssignments/delete` of an assignment whose `principalId` matches the caller, shortly after a self-grant | `AzureActivity` | Trace-cleanup pattern |

Z3, Z4 (custom role definition abuse), and any custom role granting `roleAssignments/write` collapse into the same IAM-modification detection primitive — reinforcing the W8 "primitive-not-per-path" thesis carried over from the AWS 8→4 result.

## Cleanup

```bash
cd environments/scenarios/Z3_role_assignment_manipulation
terraform destroy -auto-approve
```

If Step 5 (`--skip-revoke` was *not* used), Terraform will emit a warning that `azurerm_role_assignment.vm_mi_user_access_admin` no longer exists (the exploit deleted it). The destroy completes successfully regardless.

Keep `baseline_azure_personal` running for Z4–Z8.

## References

- MITRE ATT&CK [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- Microsoft Learn — [Built-in role: User Access Administrator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#user-access-administrator)
- Microsoft Learn — [Role Assignments REST API — Create](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create)
- Microsoft Learn — [Built-in role definition IDs](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
