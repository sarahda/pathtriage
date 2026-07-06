# Primitive 04 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 04's detection concept is expressible in Azure. Confirms cross-cloud validity without duplicating W8 Azure-KQL implementation.

## Signal Correspondence

The AWS primitive detects: **read of a credential-bearing surface followed within a correlation window by first use of a new access key ID by a different principal sharing source IP or user-agent with the reader**.

The Azure equivalent detects: **read of a credential-bearing surface followed within a correlation window by first use of a new service principal or a new MI-scoped token by a different caller sharing IP or UA with the reader**.

Cloud-invariant primitive structure:

```
Credential storage surface read
    → observed in control-plane logs
    → correlated with subsequent auth event using previously-unseen credentials
    → attribution join via shared IP or user-agent
    → fires on read-use correspondence
```

## Azure paths covered

- **Z2** — Service Principal credential theft (App Service app_settings). Direct analogue of P7. Verified.
- **Z5** — Key Vault secret escalation. Similar structure: read secret via `secrets/read` action, subsequently use secret as auth credential. Not yet verified (W6-W7 planned).
- **Z6** — Storage account key abuse. Direct analogue of P8: `listKeys` to a storage account, then use the returned key for storage-plane access. Not yet verified.

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent | Notes |
|---|---|---|
| CloudTrail `eventName = GetFunctionConfiguration` | AzureActivity `OperationName = Microsoft.Web/sites/config/list/action` | Z2 App Service equivalent |
| CloudTrail `eventName = GetObject` on credential-file pattern | AzureActivity `OperationName = Microsoft.KeyVault/vaults/secrets/getSecret/action` | Z5 Key Vault equivalent |
| N/A | AzureActivity `OperationName = Microsoft.Storage/storageAccounts/listKeys/action` | Z6 Storage key equivalent; no direct AWS analogue for the listKeys pattern |
| CloudTrail `userIdentity.accessKeyId` | AAD SignInLogs `AppId` (for SP) or Activity Log `Caller` (for MI) | Same identity-tracking role |
| CloudTrail `sourceIPAddress` | AAD SignInLogs `IPAddress` | Direct equivalent |
| CloudTrail read+use correlation | AAD SignInLogs first-seen of AppId immediately after Key Vault read | Same correlation structure |

The correlation structure is identical: read → correlate with new-credential use → fire. Azure has an additional advantage: AAD SignInLogs surface the SP's `AppId` on every use, making credential-tracking cleaner than AWS's access-key-ID model.

## Asymmetries

### Asymmetry 1 — Credential lifetime differences

AWS long-term IAM access keys have **infinite lifetime** unless rotated (default rotation is not enforced organisation-wide). Once leaked, the same key is used until deactivated. Primitive 04's "new access key ID" detection depends on the key being previously unseen — which is true because the attacker's use is the first CloudTrail visibility of the key.

Azure Service Principal secrets have **default 2-year lifetime**, but MI tokens are 24-hour-lived and re-issued. A leaked SP secret produces a specific `AppId` in AAD SignInLogs on every use — identity tracking is cleaner than tracking access-key IDs across CloudTrail history.

**Detection implication**: Azure detection has a cleaner attribution model. AWS detection is precise (access keys are identity-scoped) but requires more complex first-seen logic across a longer history window.

### Asymmetry 2 — Credential storage surface breadth

AWS has a small, standardised set of credential storage surfaces (Lambda env vars, S3 objects, EC2 user-data). Primitive 04's surface enumeration is nearly complete for AWS.

Azure has many more storage surfaces:

- App Service `app_settings` (Z2, verified)
- Function App configuration
- Key Vault secrets (Z5, planned)
- Storage account keys (Z6, planned)
- Automation Account variables
- Logic App workflow parameters
- DevOps pipeline variables
- Configuration Manager parameter store equivalents
- Container Instance environment variables
- Managed application parameters

**Detection implication**: Azure primitive 04 requires broader surface coverage. The Z5/Z6 addition to the Azure catalogue extends surface coverage in the correct direction. Full parity with Azure's actual surface breadth is out of scope for the T2 catalogue.

### Asymmetry 3 — Access log granularity

AWS CloudTrail records the credential-bearing surface's read event (`GetFunctionConfiguration`, `GetObject`) but does not natively track *which* environment variables were retrieved (the entire config is returned as one blob). Detection relies on assuming any read of a credential-storing surface potentially leaked all its credentials.

Azure Key Vault logs record **which specific secret was retrieved** (`SecretName` field in AzureActivity). Detection can be much more targeted — only reads of secrets tagged as "credential-type" fire.

**Detection implication**: Azure has a more precise detection model for Key Vault (Z5) than AWS has for its equivalent Secrets Manager. AWS's less-granular logging means primitive 04 must accept some FP on legitimate config reads.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 04 will:

1. Reuse the read-plus-use correlation structure.
2. Use `AppId` (for SP) or `Caller` object ID (for MI) as the new-credential-tracker instead of AWS access-key-ID.
3. Include broader surface coverage: App Service (Z2), Function App, Key Vault (Z5), Storage account keys (Z6), Automation Accounts. Full breadth may require multiple queries or a UNION.
4. Leverage Key Vault's per-secret granularity for cleaner Z5 detection.
5. Note in operator documentation that Azure's per-secret logging provides better precision than AWS's per-config-blob logging.

Primitive 04's design is cloud-invariant in structure. Azure gains cleaner attribution (AppId) and better precision on Key Vault surfaces; AWS has better surface enumeration (fewer surfaces to cover).
