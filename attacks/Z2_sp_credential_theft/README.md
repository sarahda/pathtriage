# Z2 — Service Principal credential theft via App Service `app_settings`

| Field | Value |
|---|---|
| **Class** | Credential discovery |
| **MITRE ATT&CK (Cloud)** | [T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| **AWS analogue** | P7 — Lambda env-var theft |
| **Status** | Verified end-to-end (see `verification_log.txt`) |
| **Baseline** | `environments/baseline_azure_personal/` (NOT `baseline_azure`) |

## Summary

A Linux VM holds a System-Assigned Managed Identity scoped to **Website Contributor on a single Linux Web App**. That Web App has a different Service Principal's `clientSecret` stored in plaintext as an application setting (the Azure equivalent of an AWS Lambda environment variable). The VM's MI calls `POST .../sites/{app}/config/appsettings/list`, harvests the SP secret, authenticates as the SP via OAuth2 `client_credentials`, and writes a tag on the resource group — proving elevation from *Website Contributor on one app* to *Contributor at subscription scope*.

## Decision: two-subscription Azure deployment (D-Z2-01)

The UNSW Azure for Students tenant blocks Service Principal creation via Microsoft Graph (HTTP 403 `Authorization_RequestDenied`) — same constraint hit in Z1 (D-Z1-02). Z1's resolution was to model the attacker as a compromised user. Z2 cannot reuse that resolution because the **leaked credential itself** is the SP — substituting a user account loses the catalogue semantic ("credential-in-config" class via OAuth2 SP).

Resolution: Z2 (and Z3-Z8) deploys on a **separate Azure subscription tied to a personal Microsoft Account**, where the operator is the sole AAD admin and SP creation is unrestricted. AWS catalogue uses a single account; Azure catalogue uses two subscriptions (UNSW Azure for Students for Z1, personal MSA for Z2-Z8) — same scenario semantics, different administrative boundary. Mirrors real-world cloud security research where institutional tenant policies frequently constrain attacker modelling.

Elevated SP is pre-created via `az ad sp create-for-rbac` (out of Terraform); its `clientId`/`secret`/`tenantId`/`objectId` are passed in via `TF_VAR_*` env vars. Terraform never touches AAD object lifecycle.

## Attack chain

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

## Implementation notes

**Tag write API quirk (engineering log)**: `Microsoft.Resources/tags/default` PATCH with api-version `2021-04-01` requires a top-level `operation` field (`Merge` / `Replace` / `Delete`) in addition to `properties.tags`. Omitting it returns HTTP 400 even with sufficient RBAC. The exploit uses `operation: "Merge"` so existing RG tags (`Project=PathTriage`, etc.) are preserved.

## Prerequisites

- `az` logged in to **personal MSA** subscription (NOT UNSW)
- `baseline_azure_personal` already applied (provides RG, VNet, subnet)
- `~/.ssh/id_rsa.pub` present
- Owner on the personal MSA subscription
- Subscription set explicitly (`ARM_SUBSCRIPTION_ID`) — azurerm provider's auto-detection hangs on macOS with multiple subscription contexts

## Deploy

```bash
# context check
az account show --query name -o tsv   # personal MSA, not UNSW

# pre-create elevated SP
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

cd environments/scenarios/Z2_sp_credential_theft
terraform init && terraform apply -auto-approve
```

## Run exploit

```bash
terraform output -json > /tmp/z2_output.json
VM_IP=$(jq -r '.vm_public_ip.value' /tmp/z2_output.json)

scp ../../../attacks/Z2_sp_credential_theft/exploit.py \
    /tmp/z2_output.json azureuser@$VM_IP:~/

ssh azureuser@$VM_IP 'cloud-init status --wait && \
    python3 exploit.py --tf-output z2_output.json --log verification_log.txt'

scp azureuser@$VM_IP:~/verification_log.txt \
    ../../../attacks/Z2_sp_credential_theft/verification_log.txt
```

## PathTriage scoring inputs (rubric v1, pre-W6 calibration)

| Input | Ordinal | Reasoning |
|---|---|---|
| Privilege uplift | **High** | Website Contributor (1 app) → Contributor (entire subscription) |
| Detectability | **Medium** | AAD sign-in for SP logged by default; `appsettings/list` in Activity log; full chain requires MI→SP correlation |
| Prerequisites | **Low** | Any identity with `Microsoft.Web/sites/config/list/Action` on an app whose settings contain secrets |
| Blast radius | **High** | Subscription control-plane |

## Detection preview (full rules in W8 defender-output module)

| Signal | Source | Primitive |
|---|---|---|
| `appsettings/list` by an MI that has never before touched that app | `AzureActivity` | `OperationNameValue == "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION"` + caller baseline |
| SP first-ever ARM sign-in | `AADServicePrincipalSignInLogs` | New-identity-new-IP join |
| SP performs `tag/write` or `roleAssignments/write` after baseline read-only | `AzureActivity` | Behavioural baseline anomaly |

## Cleanup

```bash
cd environments/scenarios/Z2_sp_credential_theft
terraform destroy -auto-approve

az ad sp delete --id "$TF_VAR_elevated_sp_client_id"
az ad app delete --id "$TF_VAR_elevated_sp_client_id"
```

Keep `baseline_azure_personal` running for Z3-Z8.

## References

- MITRE ATT&CK [T1552.001](https://attack.mitre.org/techniques/T1552/001/)
- Microsoft Learn — [Web Apps Config - List Application Settings](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings)
- Microsoft Learn — [Resource Tags REST API](https://learn.microsoft.com/en-us/rest/api/resources/tags/create-or-update-at-scope)
- Microsoft Learn — [Built-in role: Website Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#website-contributor)
