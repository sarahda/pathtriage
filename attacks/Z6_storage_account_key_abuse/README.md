# Z6 — Storage Account Key Abuse (via tfstate credential harvest)

## Overview

A VM with a System-Assigned **Managed Identity (MI)** is granted the built-in **`Storage Account Key Operator Service Role`** on a single Azure Storage Account. That role permits calling `listKeys` — returning the account's shared access keys. The storage account contains a private container with a Terraform state file (`prod/terraform.tfstate`) that embeds Service Principal credentials in plaintext — a well-known DevOps misconfiguration.

The MI's advertised authority is minimal: it holds no data-plane RBAC role on the storage account. `az role assignment list` shows only the Key Operator role. But `listKeys` returns a shared access key, and shared access keys grant **full data-plane authority** via Azure Storage's legacy authentication scheme — bypassing AAD, RBAC, and diagnostic logging.

## Attack Flow

```
┌───────────────────────────────────────────────────────────────┐
│  VM (System-Assigned MI)                                      │
│    RBAC (control-plane): Storage Account Key Operator         │
│      → permits Microsoft.Storage/storageAccounts/listkeys      │
│    RBAC (data-plane):    none                                 │
└─────────┬─────────────────────────────────────────────────────┘
          │  ① IMDS  → ARM token (resource=management.azure.com)
          ▼
┌───────────────────────────────────────────────────────────────┐
│  ARM control plane                                            │
│    POST .../storageAccounts/{name}/listKeys?api-version=2023  │
│    permission: Microsoft.Storage/storageAccounts/listkeys ✓   │
│    response: {"keys":[{"keyName":"key1","value":"..."}, ...]} │
└─────────┬─────────────────────────────────────────────────────┘
          │  ② account key (base64, 88 chars)
          ▼
┌───────────────────────────────────────────────────────────────┐
│  Azure Storage REST (data plane)                              │
│    GET https://{sa}.blob.core.windows.net/infrastructure/     │
│                prod/terraform.tfstate                          │
│    auth: SharedKey {sa}:{HMAC-SHA256}                         │
│    (bypasses AAD/RBAC entirely — no diagnostic log by default) │
│    response: tfstate JSON                                     │
└─────────┬─────────────────────────────────────────────────────┘
          │  ③ tfstate content (JSON, ~1KB)
          ▼
┌───────────────────────────────────────────────────────────────┐
│  Client-side parse                                            │
│    walk tfstate.resources[]                                   │
│    find azuread_application → attributes                      │
│    extract .application_id + .client_secret                   │
└─────────┬─────────────────────────────────────────────────────┘
          │  ④ SP credentials (app_id, client_secret)
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
│    permission: Contributor at sub scope ✓ (via SP)            │
│    result: RG tag write succeeds                              │
└───────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

- **T1552.001** — Unsecured Credentials: Credentials In Files (tfstate is the paradigmatic case)
- **T1550.001** — Use Alternate Authentication Material: Application Access Token (SharedKey auth as alternate scheme)
- **T1078.004** — Valid Accounts: Cloud Accounts (SP as second-stage identity)
- AWS analogue: **P8** (S3 credential harvest via `.tfstate` objects). Structurally identical: privileged reader + tfstate-in-object-storage + embedded IAM keys.

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure_personal/`)
- Personal MSA subscription (D-Z2-01)
- `~/.ssh/id_rsa.pub` present (RSA only per D-Z4-04)
- `az` CLI logged in with permission to create Service Principals
- Deployer holds Owner (or Contributor + User Access Administrator) at subscription scope

## Vulnerable Configuration

Three design decisions produce the vulnerability, each independently reasonable but jointly dangerous:

1. **Shared-key access enabled** (`shared_access_key_enabled = true`). The storage account permits shared-key authentication in addition to AAD. Modern secure posture disables this (`allow_shared_key_access = false`) and forces AAD-only. Legacy configurations, however, are widespread — the vast majority of production storage accounts still permit shared-key auth for compatibility with older SDKs and third-party tools.
2. **Storing tfstate in a storage account without encryption of secrets**. Terraform's `azuread_application` resource stores `client_secret` in state in plaintext by default. Terraform documents this as a known behavior and recommends state encryption + backend access control. Many teams miss the secrets-in-state issue until an audit finds it.
3. **Broad SP privilege at subscription scope**. The embedded SP holds Contributor at subscription level. This is Z2/Z5's pattern: the same "cross-service auth vector" problem, exposed via a different discovery surface.

## Engineering Decision Log

### D-Z6-01: `Storage Account Key Operator Service Role` gives no data-plane role but full data-plane authority

**Observation.** The Key Operator role grants only `Microsoft.Storage/storageAccounts/listkeys/action` and `regenerateKey/action`. It grants **no** data-plane action (`Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`). An RBAC audit shows the identity as "control-plane only".

But `listKeys` returns the account's shared access keys, and shared access keys authenticate against the data plane directly — bypassing AAD, RBAC, and (crucially) most diagnostic-logging categories. The "control-plane only" identity is functionally a data-plane owner in disguise.

**Consequence for detection.**
- RBAC audits do not surface this as a data-plane risk.
- Storage account data-plane logging is off by default; only `StorageRead`/`StorageWrite` diagnostic settings capture blob GETs, and even then, SharedKey auth is logged with `AuthenticationType = "AccountKey"` rather than an identifiable principal.
- The bridging event — `listKeys` at the control plane — is the only signal that ties a specific MI to subsequent data-plane access. The defender-output module's Azure counterpart of primitive 04 (credential discovery) treats `listKeys` as a high-signal event for exactly this reason.

**A related built-in role**, `Storage Account Key Operator`, is often confused with the more restrictive **`Storage Blob Data Reader`** (data-plane RBAC-only, no key access). The naming similarity is a common source of misconfiguration — teams intending "read blobs" grant "key operator" instead.

### D-Z6-02: Minimal tfstate JSON is sufficient for the exploit

Real Terraform state files for non-trivial environments are 100s of KB. The Z6 blob is a compact tfstate-shaped JSON (~1 KB) with a single `azuread_application` resource containing the SP credentials. The parsing logic in `exploit.py` walks the standard tfstate schema (`resources[].instances[].attributes`) and works identically against real tfstate files, verified against a full-size state from a separate development environment.

Reproducibility rationale: keeping the lab blob compact means less state noise if the scenario is redeployed and keeps `terraform apply` fast.

## Attack Steps

1. Establish SSH access to the VM as `azureuser`.
2. From inside the VM, query IMDS for an ARM-scoped MI token.
3. `POST https://management.azure.com{storage_account_id}/listKeys?api-version=2023-01-01` with the MI token. Returns account keys.
4. Compute Azure Storage Shared-Key HMAC signature for a blob GET request (`SharedKey {account_name}:{HMAC-SHA256}` header format, per Microsoft REST API spec).
5. `GET https://{sa}.blob.core.windows.net/infrastructure/prod/terraform.tfstate` with the SharedKey authorization header. Returns tfstate content.
6. Parse the tfstate JSON, walk `resources[]`, find `azuread_application` instances, extract `application_id` and `client_secret` from `attributes`.
7. POST to AAD OAuth2 token endpoint with `grant_type=client_credentials`, scope `management.azure.com/.default`. Returns SP ARM token.
8. Use SP token to PATCH a tag on the RG. Succeeds via SP's subscription-Contributor scope.

## Running the PoC

```bash
# 0. Context
az account show --query name -o tsv     # personal MSA
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export ARM_TENANT_ID=$(az account show --query tenantId -o tsv)

# 1. Pre-create the elevated SP (not managed by Terraform per D-Z2-01)
SP_NAME="pt-z6-elevated-$(openssl rand -hex 3)"
SP_JSON=$(az ad sp create-for-rbac \
    --name "$SP_NAME" \
    --role "Contributor" \
    --scopes "/subscriptions/$ARM_SUBSCRIPTION_ID" \
    --query '{appId:appId, password:password}' \
    -o json)
export TF_VAR_elevated_sp_app_id=$(echo "$SP_JSON" | jq -r '.appId')
export TF_VAR_elevated_sp_client_secret=$(echo "$SP_JSON" | jq -r '.password')

# 2. Deploy
cd environments/scenarios/Z6_storage_account_key_abuse
terraform init && terraform apply -auto-approve
sleep 30    # role propagation

# 3. Ship exploit
terraform output -json > /tmp/z6_output.json
VM_IP=$(jq -r '.vm_public_ip.value' /tmp/z6_output.json)

SSH_OPTS=(-i ~/.ssh/id_rsa \
          -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
          -o PubkeyAcceptedAlgorithms=+ssh-rsa \
          -o HostKeyAlgorithms=+ssh-rsa)

scp "${SSH_OPTS[@]}" \
    ../../../attacks/Z6_storage_account_key_abuse/exploit.py \
    /tmp/z6_output.json azureuser@$VM_IP:~/

# 4. Execute
ssh "${SSH_OPTS[@]}" azureuser@$VM_IP \
    'cloud-init status --wait && \
     python3 exploit.py --tf-output z6_output.json --log verification_log.txt'
```

## Captured Output (PoC Verification)

The full sanitized PoC log is committed as `verification_log.txt`. The raw log (containing actual subscription, tenant, MI principal, storage account name/ID, and SP app ID) is retained in `~/.pathtriage-private/`.

The exploit produces a final verification line of the form:

```
[+] Path Z6 verified: VM MI (Storage Account Key Operator on 1 SA) ->
                      listKeys via ARM -> storage account key ->
                      GET blob via SharedKey auth (bypasses AAD/RBAC) ->
                      parse tfstate -> embedded SP credentials ->
                      OAuth2 client_credentials -> SP ARM token ->
                      RG-wide control-plane writes succeed
```

## Z5 vs Z6 — Why Both Belong in the Catalogue

Both paths implement the credential-discovery primitive; both end with SP-token escalation. The distinction is the **discovery surface** — which shapes both the detection query and the preventive control.

| Dimension | Z5 (Key Vault) | Z6 (Storage account) |
|---|---|---|
| Storage surface class | Intended secret storage | Unintended (DevOps leak) |
| Retrieval primitive | `secrets/get` via KV data-plane token | `listKeys` via ARM control-plane, then blob GET via SharedKey |
| Auth model on retrieval | AAD (KV-scoped token) | SharedKey (bypasses AAD entirely) |
| Data-plane logging by default | Off (requires KV diagnostic settings) | Off (requires storage diagnostic settings) |
| Preventive gate | Disable KV secrets access model, use Managed Identity federation | Disable shared-key access (`allow_shared_key_access = false`) |
| Extraction | Direct (secret value = credential) | Parse (tfstate/env-file parsing) |
| Signal for defender | `secrets/getSecret` event with rare-reader baseline | `listKeys/action` + subsequent SharedKey blob access correlation |
| Common misconfiguration | SP secret in vault + broad SP scope | tfstate in blob + shared-key auth enabled |

A defender detecting only one of the two primitives misses the other class entirely. The defender-output module's Azure counterpart of primitive 04 covers both via distinct queries — the shared "credential discovery" concept splits into surface-specific detection at implementation time.

## Comparison to AWS Analogue

| Dimension | AWS P8 (S3 tfstate) | Azure Z6 (Storage account key) |
|---|---|---|
| Discovery surface | S3 object body | Storage account blob body |
| Bypass primitive | None — S3 read requires an identity | `listKeys` → shared-key auth bypasses IAM entirely |
| Read auth model | Always IAM | SharedKey (legacy) or AAD (modern) |
| Read event visibility | CloudTrail `s3:GetObject` | Storage diagnostic (off by default) + `listKeys` (ARM Activity Log) |
| Bridging step | Direct: IAM identity reads S3 object | Indirect: MI's `listKeys` → SharedKey → blob (three-step chain) |
| Preventive control | S3 bucket policy denying credential-file paths | Disable shared-key access at storage account level |
| Structural weakness | Object naming patterns can evade content filters | Key-based auth exists as a legacy compatibility feature |

The Azure model has a **structural weakness AWS does not have**: the `listKeys` + SharedKey auth path exists specifically to support legacy Azure Storage SDK compatibility. AWS never had an equivalent — S3 has always required IAM-based auth. Azure's shared-key model is a design decision that predates AAD-based storage auth and is now a permanent legacy surface. Documented as a comparative finding for thesis Section 4.

## Detection Preview (full rules in W8 defender-output module)

| Signal | Source | Primitive |
|---|---|---|
| `Microsoft.Storage/storageAccounts/listkeys/action` by an MI/SP whose baseline never calls listKeys | `AzureActivity` | Baseline-anomaly on caller |
| `listKeys` followed within 10 minutes by shared-key blob access from a matching IP or user-agent | `AzureActivity` + storage diagnostic (correlated) | Key exfil + immediate re-use |
| SharedKey authentication events on a storage account whose owner has `allow_shared_key_access = false` recommended | Storage diagnostic + config drift | Preventive control gap |
| New AAD SignIn from a Service Principal whose `AppId` matches a value found in any storage account's tfstate blob | AAD SignInLogs + inventory correlation | Credential re-use, post-discovery |

Note that the strongest detection requires two conditions AWS does not require: (1) storage diagnostic logs must be explicitly enabled, and (2) `listKeys` + SharedKey correlation must be computed across two different log sources. This gap is what makes Z6 detection harder than P8 detection despite the primitives being structurally similar. Documented as a limitation in the module.

## Cleanup

```bash
cd environments/scenarios/Z6_storage_account_key_abuse
terraform destroy -auto-approve

# Remove the pre-created SP
source ~/.pathtriage-private/z6_sp.env
az ad sp delete --id "$TF_VAR_elevated_sp_app_id"
```

Keep `baseline_azure_personal` running for Z7-Z8.

## References

- MITRE ATT&CK [T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- MITRE ATT&CK [T1550.001 — Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- Microsoft Learn — [Storage account authorization models](https://learn.microsoft.com/en-us/azure/storage/common/authorization-resource-provider)
- Microsoft Learn — [Prevent shared key authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)
- Microsoft Learn — [Storage Account Key Operator role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage-account-key-operator-service-role)
- Terraform docs — [Sensitive data in state](https://developer.hashicorp.com/terraform/language/state/sensitive-data)
- Microsoft Learn — [Authorize with Shared Key REST spec](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
