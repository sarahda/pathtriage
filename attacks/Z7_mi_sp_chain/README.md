# Z7 — MI / Service Principal Chain (Role Assignment Cascade)

## Overview

A VM has two Service Principal credentials embedded on disk. **SP-A** holds `User Access Administrator` on the resource group — grant authority, but no ability to write resources itself. **SP-B** starts with no permissions on the resource group. The attacker chains through both identities: uses SP-A's grant authority to elevate SP-B, then acts through SP-B with the newly granted authority.

The key structural point: SP-A holds no `Microsoft.Resources/tags/write` action anywhere. It cannot perform the escalation write directly. But its UAA authority lets it grant Contributor to *any* principal — including SP-B, which the attacker also controls. Two identities under attacker control, one grant event, escalation complete.

## Attack Flow

```
┌───────────────────────────────────────────────────────────────┐
│  Attacker's foothold                                          │
│    SSH access to VM                                           │
│    ↓ reads /home/azureuser/app_config.json                    │
│    ↓ obtains SP-A and SP-B client secrets                     │
└─────────┬─────────────────────────────────────────────────────┘
          │  ① two SP credential sets acquired
          ▼
┌───────────────────────────────────────────────────────────────┐
│  SP-A (User Access Administrator on RG)                       │
│    baseline: cannot write resources of any kind               │
│    baseline: CAN grant any role (UAA authority)               │
│                                                                │
│    ↓ client_credentials → ARM token                           │
│    ↓ PUT /roleAssignments/{guid}?api-version=2022-04-01       │
│        principalId:      SP-B's object ID                     │
│        principalType:    ServicePrincipal                     │
│        roleDefinitionId: Contributor                          │
│        scope:            /resourceGroups/pathtriage-rg        │
└─────────┬─────────────────────────────────────────────────────┘
          │  ② role assignment created (HTTP 201)
          │  ③ wait ~45s for propagation
          ▼
┌───────────────────────────────────────────────────────────────┐
│  SP-B (now Contributor on RG via SP-A's grant)                │
│    baseline WAS: no permission on this RG                     │
│    now: Contributor on RG scope                               │
│                                                                │
│    ↓ client_credentials → ARM token                           │
│    ↓ token claims: appid=SP-B (not SP-A)                      │
└─────────┬─────────────────────────────────────────────────────┘
          │  ④ SP-B ARM token, now backed by Contributor scope
          ▼
┌───────────────────────────────────────────────────────────────┐
│  ARM control plane (as SP-B)                                  │
│    PATCH /subscriptions/{sub}/resourceGroups/{rg}/            │
│          providers/Microsoft.Resources/tags/default           │
│    operation=Merge                                            │
│    result: 200 OK — SP-B's Contributor scope allows the write │
└───────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

- **T1078.004** — Valid Accounts: Cloud Accounts (both SP-A and SP-B as valid identities under attacker control)
- **T1098** — Account Manipulation (SP-A modifies SP-B's authority via role assignment)
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- AWS analogue: **P4** (AssumeRole Chain). Same primitive class (trust topology), but the chain mechanic differs substantially — see Comparison section.

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure_personal/`)
- Personal MSA subscription (D-Z2-01)
- `~/.ssh/id_rsa.pub` present (RSA only per D-Z4-04)
- `az` CLI logged in with permission to create Service Principals AND to assign the User Access Administrator role
- Deployer holds Owner at subscription scope

## Vulnerable Configuration

Three design decisions produce the vulnerability, each independently reasonable:

1. **SP-A holds User Access Administrator at RG scope**. Realistic scenario — many DevOps automation identities need to grant roles to newly-provisioned service accounts. UAA is often granted for this purpose.
2. **SP-B credentials coexist with SP-A on the same VM**. Any identity with disk read on the VM controls both SPs, giving the attacker the target endpoint for the chain.
3. **No preventive control on WHICH principals SP-A can grant roles to**. Azure UAA is untargeted — it can grant to any principal in the tenant, including one the attacker controls. Constrained UAA (e.g., only granting to principals in a specific management group) is not a native feature.

## Engineering Decision Log

### D-Z7-01: Cloud-init cannot embed secrets on Azure Linux VMs reliably

**Observation.** The initial design embedded SP-A and SP-B credentials via cloud-init's `write_files` module. Cloud-init reported `status: error` at first boot with the message:

```
('write_files', OSError('Unknown user or group: "getpwnam(): name not found: \'azureuser\'"'))
```

Further inspection: `/home/azureuser` was owned by `root:root`, not `azureuser:azureuser`, even though the user existed and SSH login succeeded.

**Root cause.** Azure Linux VMs create the admin SSH user via the Azure Guest Agent (waagent), not via cloud-init's `users` module. Cloud-init's `write_files` module runs before waagent completes user provisioning, so any file whose owner is the admin user fails with "user not found". This also cascades — cloud-init leaves `/home/azureuser` in an inconsistent ownership state, blocking subsequent SSH-based file writes into the home directory until an explicit `chown` is performed.

**Resolution.**
- Attempted: `sudo chown azureuser:azureuser ~/` from an SSH session (NOPASSWD sudo is enabled by default) — this works.
- Deployed: credentials are shipped to the VM via SCP after VM boot and manual chown. `terraform apply` provisions the VM; a separate manual step ships credentials.

**Implication for reproducibility.** The Z7 lab has a two-step deployment (terraform apply + credential SCP) rather than the fully self-contained pattern of Z1-Z6. Documented explicitly in the "Running the PoC" section. In production, secret injection should use post-deployment tooling (Ansible, Bicep with Key Vault reference, or Custom Script Extension after VM is Ready), not cloud-init.

### D-Z7-02: Azure OBO flow requires user delegation — SP-to-SP OBO is structurally blocked

**Attempted design.** Initial Z7 approach was OAuth 2.0 On-Behalf-Of (OBO) token exchange as the direct semantic equivalent of AWS `sts:AssumeRole` chained impersonation. SP-A would obtain an initial token, then perform OBO exchange to obtain a token representing SP-B.

**Result.** OBO exchange returned HTTP 400 with error `AADSTS500131`:

> "Assertion audience does not match the Client app presenting the assertion. The audience in the assertion was 'SP-B-app-id' and the expected audience is 'SP-A-app-id'"

**Root cause.** Azure OBO requires the initial assertion token to have `aud=SP-A` (the app presenting the OBO request). This audience only exists in **user delegation flows** — when a user signs in to SP-A via UI or MFA, the resulting token has `aud=SP-A`. Pure `client_credentials` flow cannot produce a self-audience token; Azure explicitly refuses to issue `aud=SP-A` tokens via client_credentials.

**Structural consequence.** Azure prevents pure SP-to-SP chained impersonation at the identity platform level. AWS `sts:AssumeRole` has no equivalent user-delegation requirement — any principal (user or role) can chain assume any role whose trust policy permits it, purely programmatically. This is a **structural asymmetry**: AWS P4's attack surface (pure programmatic identity chaining) does not exist in Azure at all.

**Resolution.** Pivoted Z7 approach from OBO-based impersonation to role-assignment cascade. Attack semantic changes:
- OBO would model "SP-A becomes SP-B" (session-level chain).
- Cascade models "SP-A grants authority to SP-B" (authorization-level chain).

Both are trust-topology attacks but the detection surfaces differ substantially — cascade is visible in Activity Log as a `roleAssignments/write` event, OBO would have been in AAD SignInLogs as a token exchange event. The Azure detection primitive for trust topology must therefore reason about role-assignment cascades, not session chains.

This D-Z7-02 finding is the primary Z7 comparative contribution to thesis Section 4. It represents a case where an entire class of AWS attacks has no direct Azure analogue due to Azure's identity platform design.

### D-Z7-03: Role assignment propagation timing is unpredictable

**Observation.** After SP-A creates the role assignment for SP-B, subsequent SP-B operations may return 403 if executed too quickly. The role assignment is created immediately at the ARM API level (`roleAssignments/write` returns 201 in ~1 second), but the token validation layer requires propagation.

**Measurement.** Across multiple Z7 runs during development:
- < 30s: often fails (50%+ 403 rate)
- 30-45s: usually succeeds (~90%)
- 45-60s: reliably succeeds

**Resolution.** The exploit waits 45 seconds after grant. This is longer than needed on average but ensures reliability. In production attack scenarios, an attacker would poll (attempt the escalation write, retry on 403) rather than pre-wait. Documented as a detection opportunity — the propagation gap between grant and use is itself a signal window.

## Attack Steps

1. Establish SSH access to the VM as `azureuser`.
2. Read `/home/azureuser/app_config.json` to obtain SP-A and SP-B credentials.
3. Acquire SP-A ARM token via OAuth2 client_credentials.
4. Issue `PUT /subscriptions/.../resourceGroups/.../providers/Microsoft.Authorization/roleAssignments/{guid}?api-version=2022-04-01` with SP-A's token:
    - `principalId`: SP-B's object ID
    - `principalType`: `ServicePrincipal`
    - `roleDefinitionId`: Contributor built-in role
    - `scope`: RG scope
5. Wait ~45 seconds for role assignment propagation.
6. Acquire SP-B ARM token via OAuth2 client_credentials. SP-B's token now carries Contributor authority on the RG.
7. Use SP-B token to PATCH tag on RG. Succeeds via Contributor scope granted in step 4.

## Running the PoC

```bash
# 0. Context
az account show --query name -o tsv     # personal MSA
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export ARM_TENANT_ID=$(az account show --query tenantId -o tsv)

# 1. Create SP-A (User Access Administrator on RG)
SP_A_NAME="pt-z7-attacker-$(openssl rand -hex 3)"
SP_A_JSON=$(az ad sp create-for-rbac \
    --name "$SP_A_NAME" \
    --query '{appId:appId, password:password, id:id}' \
    -o json)
SP_A_APP_ID=$(echo "$SP_A_JSON" | jq -r '.appId')
SP_A_SECRET=$(echo "$SP_A_JSON" | jq -r '.password')
az role assignment create \
    --assignee-object-id $(az ad sp show --id $SP_A_APP_ID --query id -o tsv) \
    --assignee-principal-type ServicePrincipal \
    --role "User Access Administrator" \
    --scope "/subscriptions/$ARM_SUBSCRIPTION_ID/resourceGroups/pathtriage-rg"

# 2. Create SP-B (empty baseline — no roles)
SP_B_NAME="pt-z7-elevated-$(openssl rand -hex 3)"
SP_B_JSON=$(az ad sp create-for-rbac \
    --name "$SP_B_NAME" \
    --skip-assignment \
    --query '{appId:appId, password:password, id:id}' \
    -o json)
SP_B_APP_ID=$(echo "$SP_B_JSON" | jq -r '.appId')
SP_B_SECRET=$(echo "$SP_B_JSON" | jq -r '.password')
SP_B_OBJECT_ID=$(az ad sp show --id $SP_B_APP_ID --query id -o tsv)

# 3. Deploy VM
export TF_VAR_subscription_id=$ARM_SUBSCRIPTION_ID
export TF_VAR_tenant_id=$ARM_TENANT_ID
export TF_VAR_sp_a_app_id=$SP_A_APP_ID
export TF_VAR_sp_a_client_secret=$SP_A_SECRET
export TF_VAR_sp_b_app_id=$SP_B_APP_ID
cd environments/scenarios/Z7_mi_sp_chain
terraform init && terraform apply -auto-approve

# 4. Prepare and ship credentials (D-Z7-01: cloud-init unreliable)
terraform output -json > /tmp/z7_output.json
VM_IP=$(jq -r '.vm_public_ip.value' /tmp/z7_output.json)

cat > /tmp/z7_app_config.json << EOF
{
  "sp_a_app_id":        "$SP_A_APP_ID",
  "sp_a_client_secret": "$SP_A_SECRET",
  "sp_b_app_id":        "$SP_B_APP_ID",
  "sp_b_client_secret": "$SP_B_SECRET",
  "sp_b_object_id":     "$SP_B_OBJECT_ID",
  "tenant_id":          "$ARM_TENANT_ID"
}
EOF
chmod 600 /tmp/z7_app_config.json

SSH_OPTS=(-i ~/.ssh/id_rsa \
          -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
          -o PubkeyAcceptedAlgorithms=+ssh-rsa \
          -o HostKeyAlgorithms=+ssh-rsa)

# Fix home ownership (D-Z7-01), then ship credentials
ssh "${SSH_OPTS[@]}" azureuser@$VM_IP 'sudo -n chown azureuser:azureuser ~/'
scp "${SSH_OPTS[@]}" /tmp/z7_app_config.json azureuser@$VM_IP:~/app_config.json
scp "${SSH_OPTS[@]}" \
    ../../../attacks/Z7_mi_sp_chain/exploit.py \
    /tmp/z7_output.json azureuser@$VM_IP:~/

# 5. Execute
ssh "${SSH_OPTS[@]}" azureuser@$VM_IP \
    'chmod 600 ~/app_config.json && \
     python3 exploit.py --tf-output z7_output.json --config ~/app_config.json --log verification_log.txt'
```

## Captured Output (PoC Verification)

The full sanitized PoC log is committed as `verification_log.txt`. The raw log (containing actual subscription, tenant, SP app IDs, SP object IDs, and VM public IP) is retained in `~/.pathtriage-private/`.

The exploit produces a final verification line of the form:

```
[+] Path Z7 verified: SP-A (UAA on RG, no write authority itself) ->
                      roleAssignments/write -> Contributor to SP-B ->
                      SP-B token (Contributor via cascade grant) ->
                      RG tag write succeeds via SP-B's newly granted scope
```

## Z3 vs Z7 — Why Both Belong in the Catalogue

Both paths involve `roleAssignments/write` and end with escalated write authority. But they exercise fundamentally different trust models.

| Dimension | Z3 (Role assignment manipulation) | Z7 (Cascade chain) |
|---|---|---|
| Number of identities | 1 (self-elevation) | 2 (SP-A grants to SP-B) |
| Attack semantic | Direct self-grant | Chain via delegated grant authority |
| Primitive class | IAM modification | Trust topology |
| Detection signature | UAA/assign event with `principalId == caller` | UAA/assign event with `principalId != caller` |
| Common misconfig | UAA granted at RG or subscription scope | UAA granted to a service identity that shares disk/config with another compromised identity |

Z3 tests whether Azure blocks a principal from self-elevating to roles it doesn't hold. Z7 tests whether Azure blocks a principal from elevating *other* principals it doesn't control. The answer to both is "no, subject only to UAA scope" — but the detection surfaces are entirely different.

## Comparison to AWS Analogue

| Dimension | AWS P4 (AssumeRole Chain) | Azure Z7 (Role Cascade) |
|---|---|---|
| Chain mechanic | Session-level: `sts:AssumeRole` creates new session at each hop | Authorization-level: `roleAssignments/write` grants persistent authority |
| Log surface | Sequence of AssumeRole events (single log source: CloudTrail) | Grant event + subsequent token acquisition (two log sources: Activity Log + AAD SignInLogs) |
| Chain length limit | 5 hops (STS session policy) | 1 hop practical, unlimited theoretical |
| Timing between hops | Immediate | ~45s propagation gap |
| Preventive control | Trust policy conditions on target role | Deny UAA + tag-based grant restrictions |
| MFA propagation | Optional (session tags) | None |
| Rollback | Session expires (limited window) | Persistent (role assignment remains until deleted) |

**Structural finding**: AWS P4 and Azure Z7 exercise the same primitive class (trust topology) but through fundamentally different identity platform mechanisms. AWS uses session chaining (transient credentials), Azure uses authorization delegation (persistent grants). This affects detection primitively:
- AWS detection is a **sequence pattern** on a single log source (chained AssumeRole events with matching principal IDs).
- Azure detection is a **correlation pattern** across two log sources (Activity Log grant + AAD sign-in of the granted identity).

Combined with D-Z7-02's finding that pure SP-to-SP OBO is structurally blocked in Azure, the picture is: Azure's identity platform prevents one class of P4 attacks (session-based chains) but permits another (authorization-based cascades). AWS permits both.

## Detection Preview (full rules in W8 defender-output module)

| Signal | Source | Primitive |
|---|---|---|
| `Microsoft.Authorization/roleAssignments/write` where `caller` ≠ `principalId` (elevating someone else) | `AzureActivity` | Cascade grant |
| Grant event followed within 5 minutes by AAD SignIn from the granted principal | Activity Log + SignInLogs correlated | Grant + immediate re-use |
| SignIn from an SP whose `appid` matches a principal that was granted a role by an identity known to be low-privilege (baseline: SP-A never grants roles) | SignInLogs + baseline history | Novel-granter signal |

Note: the strongest detection requires correlating two log sources with a temporal window. Z3's detection is a single-event signature (`principalId == caller`); Z7's requires two-source correlation. Documented as the detection primitive 05 (trust topology) Azure counterpart's core query design.

## Cleanup

```bash
cd environments/scenarios/Z7_mi_sp_chain
terraform destroy -auto-approve

# Remove the role assignment created by the exploit
source ~/.pathtriage-private/z7_sps.env
SUB_ID=$(az account show --query id -o tsv)
az role assignment delete \
    --assignee $Z7_SP_B_APP_ID \
    --role "Contributor" \
    --scope "/subscriptions/$SUB_ID/resourceGroups/pathtriage-rg"

# Remove SP-A and SP-B
az ad sp delete --id $Z7_SP_A_APP_ID
az ad sp delete --id $Z7_SP_B_APP_ID
```

Keep `baseline_azure_personal` running for Z8.

## References

- MITRE ATT&CK [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- MITRE ATT&CK [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- Microsoft Learn — [Role assignments API](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments)
- Microsoft Learn — [User Access Administrator built-in role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#user-access-administrator)
- Microsoft Learn — [OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow) (referenced in D-Z7-02)
- AWS docs — [sts:AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) (for comparison)
