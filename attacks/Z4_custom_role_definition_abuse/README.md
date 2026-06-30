# Z4 — Custom role definition abuse (mutate-role primitive)

## Overview

A VM with a System-Assigned **Managed Identity (MI)** is assigned the built-in **Owner** role at subscription scope, plus an innocuous custom "App Operator" role (read-only) at resource-group scope. The exploit injects the wildcard `*` action into the App Operator role definition's `Actions[]` via `Microsoft.Authorization/roleDefinitions/write`. Because role definitions are evaluated at authorisation time and not bound to assignments, **every existing assignee of the App Operator role is retroactively elevated** — without a single new `roleAssignment` record appearing in the audit log.

The starting role is Owner rather than User Access Administrator (UAA) **for a specific and important reason** (see D-Z4-02 below): Azure RBAC enforces an undocumented privilege-escalation guard on `roleDefinitions/write`. A principal that does not already hold a given action cannot inject that action into a role definition — the API call returns 200 OK with the echoed body, but a backend validator silently reverts the persisted state to the prior version within seconds. UAA holds `Microsoft.Authorization/*/write` but not `*`, so UAA cannot inject `*`. Only roles that already hold the actions being injected can write them into another role.

## Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│  VM (System-Assigned MI)                                     │
│    RBAC:                                                     │
│      - Owner (built-in, subscription scope)                  │
│      - App Operator (custom, RG scope, read-only)            │
└────────┬─────────────────────────────────────────────────────┘
         │  ① IMDS  → ARM token (resource=management.azure.com)
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  GET .../roleDefinitions/<App Operator GUID>            │
│       inventory: 4 read-only actions                         │
└────────┬─────────────────────────────────────────────────────┘
         │  ② baseline role-definition snapshot
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  PUT .../roleDefinitions/<App Operator GUID>            │
│       properties.permissions[0].actions = ["*"]              │
│       requires: caller already holds the actions being       │
│       written (Azure privilege-escalation guard, D-Z4-02)    │
└────────┬─────────────────────────────────────────────────────┘
         │  ③ inject wildcard
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  GET .../roleDefinitions/<App Operator GUID>            │
│       confirms: actions = ["*"]; mutation persisted (not     │
│       silently reverted, because caller already held "*")    │
└────────┬─────────────────────────────────────────────────────┘
         │  ④ verify mutation
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  IMDS → ARM token (fresh)                               │
│       (existing tokens do NOT reflect post-mutation perms;   │
│        a new token must be acquired — D-Z4-03)               │
└────────┬─────────────────────────────────────────────────────┘
         │  ④.5 re-acquire MI token after mutation
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  PATCH .../resourceGroups/<rg>/.../tags/default         │
│       writes succeed via the mutated App Operator role       │
│       (assignment unchanged; only the role definition was)   │
└──────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

- **T1098** — Account Manipulation
- **T1078.004** — Valid Accounts: Cloud Accounts
- AWS analogue: **P3 — CreatePolicyVersion** (mutate-policy primitive)

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure_personal/`)
- Personal MSA subscription (D-Z2-01)
- `~/.ssh/id_rsa.pub` present (RSA only; provider v3 limitation, D-Z4-04)
- `az` CLI logged in; `ARM_SUBSCRIPTION_ID` / `ARM_TENANT_ID` exported
- Operator must hold Owner at subscription scope (Terraform assigns Owner to the VM MI at apply-time)

## Vulnerable Configuration

The Z4 scenario provisions exactly one over-broad grant:

- VM System-Assigned MI is granted built-in `Owner` at **subscription scope**.
- The MI is also assigned a custom `App Operator` role at RG scope (read-only). This is the **mutation target**, not the misconfiguration — the App Operator role is benign on its own.

No separate attacker identity is required. The MI exploits its Owner capability against a role definition that it itself holds (App Operator).

## Engineering Decision Log

Z4 surfaced four findings during initial verification. All four are material to interpreting the result and to the W8 defender-output module's IAM-modification primitive design.

### D-Z4-01: RG-scoped `roleDefinitions/write` cannot rewrite a custom role definition

**Observation.** A custom role granted only at RG scope and including `Microsoft.Authorization/roleDefinitions/write` cannot modify any role definition. HTTP `PUT` returns `403 AuthorizationFailed`.

**Root cause.** Custom role *definitions* live at subscription scope in ARM (`/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{guid}`) regardless of where they are *assignable*. The authorisation check is performed against the definition object's own scope, not the calling scope.

**Resolution.** Granting role must be assigned at subscription scope. Z4's Owner assignment is therefore made at sub scope, not RG scope.

### D-Z4-02: Azure silently reverts role-definition mutations that exceed the caller's own permissions

**Observation.** Even with subscription-scope `User Access Administrator`, which advertises `Microsoft.Authorization/*/write`, an attempt to inject `*` into a custom role's `actions[]` returns 200 OK with the echoed body — but a follow-up `GET` within seconds shows the prior `actions[]` restored. The mutation is silently reverted. Substituting Owner (which already holds `*`) for the calling role allows the same `PUT` to persist.

**Hypothesis (validated experimentally).** Azure RBAC enforces a service-side privilege-escalation guard at the `Microsoft.Authorization` resource provider: a principal whose own roles do not include action `A` cannot inject `A` into any other role's `actions[]`. UAA can write role definitions whose actions UAA already holds, but not actions it does not. Owner, which holds `*`, can inject anything. This guard is **not** documented in Microsoft's public RBAC reference.

**Verification.** Two end-to-end runs against identical infrastructure differing only in the calling role:

| Starting role | `PUT roleDefinitions` HTTP code | `GET` after 5s | Step 5 (write via mutated role) |
|---|---|---|---|
| User Access Administrator (sub scope) | 200 OK | actions reverted to read-only | 403 AuthorizationFailed |
| Owner (sub scope) | 200 OK | actions persist as `["*"]` | succeeds |

**Asymmetry with AWS.** This is a structural divergence from the AWS analogue. AWS treats IAM policy actions as the sole source of truth: `iam:CreatePolicyVersion` permits any actions to be written into any version, regardless of whether the caller themselves holds those actions. Azure interposes a privilege-escalation guard absent in AWS. PathTriage's comparative analysis treats this as a quantitative difference in the two clouds' privilege models — Azure provides **structural prevention** for the mutate-policy primitive, AWS provides only **reactive detection**.

**Practical implication.** This narrows but does not eliminate Z4 in the real world. Attackers cannot use UAA-equivalent custom roles to escalate via this primitive. But any identity that already holds Owner (or any role containing the wildcard actions to be injected) can use the primitive to *grant the wildcard to other identities silently* — the mutated role definition affects every assignee retroactively, leaving no `roleAssignment` audit trail.

### D-Z4-03: MI tokens do not reflect post-mutation permissions; a fresh IMDS token is required

**Observation.** Step 3 mutates the role definition successfully. Step 5 (a write that the mutated role should permit) returns 403 if executed with the same Bearer token used for Steps 1-3. Re-acquiring the IMDS token between mutation and write makes Step 5 succeed.

**Root cause.** Azure AD access tokens carry permission claims established at issuance. Changes to the underlying role definition do not propagate to in-flight tokens. The token-bound permission model differs from AWS, where in-flight STS credentials reflect IAM permission changes nearly immediately (eventual consistency is short).

**Detection implication.** The high-confidence Z4 signature is: same MI principal → `roleDefinitions/write` → fresh IMDS token request → control-plane write — all within seconds. The token-refresh step is necessary to the attack and gives defenders a corroborating signal independent of the mutation itself.

### D-Z4-04: Azure provider v3 admin_ssh_key requires RSA; Ubuntu 22.04 sshd requires explicit RSA-SHA2 negotiation

**Observation.** Two stacked failures at the SSH layer during initial Z4 verification:

1. `terraform apply` rejected `id_ed25519` with `Only RSA SSH keys are supported by Azure`. The azurerm provider v3 restricts `admin_ssh_key.public_key` to RSA. (Provider v4 lifts this.)
2. With the RSA key accepted by Terraform, `ssh` from macOS still failed `Permission denied (publickey)` because Ubuntu 22.04 sshd disables SHA-1 RSA signatures by default and macOS OpenSSH defaults to SHA-1.

**Resolution.** Workstation `~/.ssh/config` declares `PubkeyAcceptedAlgorithms +ssh-rsa` and `HostKeyAlgorithms +ssh-rsa` for the relevant Azure IP ranges. No change to the lab Terraform.

### D-Z4-05: Custom role definition CREATE and DELETE are slow

**Observation.** `terraform apply` / `destroy` of scenarios containing custom role definitions can take 5–10 minutes per role, polling every 10 seconds. Backend AAD propagation is asynchronous.

**Resolution.** Treated as a known cost. If a destroy exceeds 10 minutes, escape with `terraform state rm azurerm_role_definition.<name>` and manually delete the role via `az role definition delete`. Standard workflow time-budgeting for Z4 should assume ~8 minutes of Terraform polling per apply/destroy cycle.

## Why Owner (not UAA) is the operative starting role

The catalogue's first design used UAA — `User Access Administrator` looked closer to a realistic "least-privilege custom-role-manager" misconfiguration, and is what most cloud security blog posts list as the role to watch for mutation primitives. The experimental result that UAA mutations silently revert (D-Z4-02) forced the redesign to Owner.

This is a **catalogue-positive** outcome. The realistic threat surface for Z4 is narrower than for the AWS analogue P3: only Owner-equivalent identities can execute the primitive in Azure. The defensive corollary is that a defender who restricts Owner assignments tightly is structurally protected from Z4 — a stronger property than the AWS equivalent provides.

The Z3 (`roleAssignments/write`) primitive is unaffected by this guard; Z3 remains executable from UAA. The two paths therefore have different starting-role requirements despite belonging to the same IAM-modification class, which is itself a finding worth recording.

## Attack Steps

1. Establish SSH access to the VM as `azureuser`.
2. From the VM, query IMDS at `169.254.169.254` for an ARM-scoped Bearer token.
3. `GET .../roleDefinitions/{appOperatorGuid}?api-version=2022-04-01` and snapshot baseline actions.
4. `PUT .../roleDefinitions/{appOperatorGuid}` with `actions=["*"]`. Persists because the caller (Owner) already holds `*`.
5. `GET` again to confirm persistence.
6. Re-issue IMDS token (D-Z4-03).
7. `PATCH .../resourceGroups/{rg}/.../tags/default` with `operation: Merge` using the fresh token. Succeeds via the mutated App Operator role.

## Running the PoC

```bash
# 0. context
az account show --query name -o tsv     # personal MSA
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export ARM_TENANT_ID=$(az account show --query tenantId -o tsv)

# 1. deploy (~3-5 min; D-Z4-05)
cd environments/scenarios/Z4_custom_role_definition_abuse
terraform init && terraform apply -auto-approve
sleep 60                                # Owner-at-sub-scope propagation

# 2. ship exploit
terraform output -json > /tmp/z4_output.json
VM_IP=$(jq -r '.vm_public_ip.value' /tmp/z4_output.json)

SSH_OPTS=(-i ~/.ssh/id_rsa \
          -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
          -o PubkeyAcceptedAlgorithms=+ssh-rsa \
          -o HostKeyAlgorithms=+ssh-rsa)

scp "${SSH_OPTS[@]}" \
    ../../../attacks/Z4_custom_role_definition_abuse/exploit.py \
    /tmp/z4_output.json azureuser@$VM_IP:~/

# 3. execute
ssh "${SSH_OPTS[@]}" azureuser@$VM_IP \
    'cloud-init status --wait && \
     python3 exploit.py --tf-output z4_output.json --log verification_log.txt'

# 4. retrieve log
scp "${SSH_OPTS[@]}" azureuser@$VM_IP:~/verification_log.txt \
    ../../../attacks/Z4_custom_role_definition_abuse/verification_log.txt
```

## Captured Output (PoC Verification)

The full sanitized PoC log is committed as `verification_log.txt`. The raw log (containing actual subscription, tenant, MI principal, and role definition GUIDs) is retained in `~/.pathtriage-private/`.

The exploit produces a final verification line of the form:

```
[+] Path Z4 verified: VM MI (custom role w/ roleDefinitions/write) ->
                      PUT roleDefinitions injecting '*' into Actions ->
                      every assignee of the mutated role now Owner-equivalent ->
                      RG-wide control-plane writes succeed
```

## Z3 vs Z4 — Why Both Belong in the Catalogue

| Dimension | Z3 (Role assignment manipulation) | Z4 (Role definition mutation) |
|---|---|---|
| Starting role | UAA on RG | **Owner on subscription** (D-Z4-02) |
| Primitive exercised | `roleAssignments/write` | `roleDefinitions/write` |
| ARM API verb | `PUT .../roleAssignments/{guid}` | `PUT .../roleDefinitions/{guid}` |
| Audit event surface | `Microsoft.Authorization/roleAssignments/write` | `Microsoft.Authorization/roleDefinitions/write` |
| Visibility in `az role assignment list` | New row appears | **No change** — affects existing rows |
| Retroactive effect on third parties | None | All current assignees of mutated role |
| Subject to privilege-escalation guard? | No | **Yes (D-Z4-02)** |
| AWS analogue | P5 — `iam:AttachUserPolicy` self-attach | P3 — `iam:CreatePolicyVersion` |

Z4's narrower starting-role requirement is not a flaw of the path — it is **Azure structurally restricting an attack class that AWS does not restrict**. Documenting both is necessary to make the comparative analysis honest.

## Comparison to AWS Analogue

| Dimension | AWS P3 (CreatePolicyVersion) | Azure Z4 (Role definition mutation) |
|---|---|---|
| Required action | `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` | `Microsoft.Authorization/roleDefinitions/write` |
| Required starting authority | Any policy with the required actions | **The caller must already hold the actions being injected** (D-Z4-02) |
| Mutation target | Customer-managed IAM policy | Custom role definition |
| Persistence after mutation | Always | **Only if caller already held the new actions** |
| Cross-principal effect | All principals with the policy attached | All assignees of the role |
| Cloud-side prevention | **None** — reactive detection only | **Yes** — service-side privilege-escalation guard |
| Token semantics after mutation | In-flight STS credentials reflect new actions nearly immediately | **Existing MI/SP tokens do NOT reflect new actions; fresh token required** (D-Z4-03) |
| Detectable as discrete event | CloudTrail `CreatePolicyVersion` | Activity Log `roleDefinitions/write` |

Rows 6 and 7 are material to thesis Section 4. AWS's privilege model is fully self-describing and lacks an escalation guard; Azure's interposes one. AWS's token model propagates IAM changes; Azure's binds capability to the token at issuance. Both differences make Azure's Z4 substantially harder to execute and easier to detect than its AWS analogue — but neither is documented in either vendor's reference material.

## Detection Preview (full rules in W8 defender-output module)

| Signal | Source | Primitive |
|---|---|---|
| `roleDefinitions/write` by a principal whose prior history at the same scope is read-only | `AzureActivity` | Baseline-anomaly on caller |
| `roleDefinitions/write` where new `actions[]` contains entries not present in the prior version, *and* a follow-up GET within 10 seconds confirms persistence (mutation was not silently reverted) | `AzureActivity` correlated with state | Successful-elevation pattern (filters out attempts blocked by D-Z4-02) |
| Same MI/SP issues `roleDefinitions/write` → fresh IMDS token → control-plane write within 60 seconds | `AzureActivity` + AAD `SignInLogs` correlated | High-confidence Z4 chain (per D-Z4-03) |

The second signal explicitly leverages D-Z4-02 to suppress noise: attempts that Azure already blocks server-side are not actionable, so the primitive is gated on persistence verification.

## Cleanup

```bash
cd environments/scenarios/Z4_custom_role_definition_abuse
terraform destroy -auto-approve
```

Per D-Z4-05, destroy may take 5-10 minutes. Keep `baseline_azure_personal` running for Z5-Z8.

## References

- MITRE ATT&CK [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- Microsoft Learn — [Built-in role: Owner](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner)
- Microsoft Learn — [Built-in role: User Access Administrator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#user-access-administrator)
- Microsoft Learn — [Custom roles in Azure RBAC](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)
- Microsoft Learn — [Role Definitions REST API](https://learn.microsoft.com/en-us/rest/api/authorization/role-definitions)
