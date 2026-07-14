# Primitive 04 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 04's detection concept is expressible in Azure. Confirms cross-cloud validity without duplicating W8 Azure-KQL implementation.

## Signal Correspondence

The AWS primitive detects: **credential-bearing surface read followed by first-use of a novel access key by a different principal within a correlation window**.

The Azure equivalent detects: **secret-bearing surface read followed by first-use of a Service Principal token acquired via the leaked secret**.

Cloud-invariant primitive structure:
Credential-bearing surface read event
 → observed in control-plane or data-plane logs
→ correlated with subsequent token acquisition
→ correlated with subsequent write action by that token
→ fires when the credential first-use is by a different principal
sharing network/UA characteristics

## Azure paths covered

Three verified Azure paths exercise this primitive across distinct discovery surfaces. This is the primitive with the highest per-primitive path density in the catalogue.

- **Z2** — Service Principal secret leaked in App Service `app_settings`
- **Z5** — Service Principal secret stored in Key Vault
- **Z6** — Service Principal credentials embedded in Terraform state blob (via Storage Account key extraction)

Each exercises the same primitive class but through a fundamentally different discovery surface, which shapes both the detection query and the preventive control.

## Discovery surface comparison across all 5 paths

| Path | Surface | Retrieval Mechanism | Storage class |
|---|---|---|---|
| P7 (AWS) | Lambda env vars | `lambda:GetFunctionConfiguration` | Configuration metadata |
| P8 (AWS) | S3 object (credential file) | `s3:GetObject` on `.env`/`.tfstate` patterns | Unintended (DevOps leak) |
| Z2 (Azure) | App Service `app_settings` | `sites/config/list` via `Website Contributor` | Configuration metadata |
| Z5 (Azure) | Key Vault secret | `secrets/get` via `Key Vault Secrets User` | **Intended** secret storage |
| Z6 (Azure) | Storage Account blob (tfstate) | `listKeys` → SharedKey → blob GET | Unintended (DevOps leak) |

Two dimensions of variation matter for detection:

1. **Intended vs unintended storage**. Z5 exploits credentials in the *right* place (Key Vault is Microsoft's recommended secret storage). Z2/Z6/P7/P8 exploit credentials in the *wrong* place. Detection heuristics differ: Z5 requires baseline reasoning about who *should* read which vault; Z2/Z6/P7/P8 can use content-pattern detection at storage time.
2. **Auth path for retrieval**. Z6 uniquely bypasses AAD/RBAC via shared-key authentication after retrieving the account key. This is a structural weakness AWS S3 does not have. Documented in Asymmetry 4 below.

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent (Z2) | Azure equivalent (Z5) | Azure equivalent (Z6) |
|---|---|---|---|
| `eventName = GetFunctionConfiguration` | `Microsoft.Web/sites/config/list` action | `Microsoft.KeyVault/vaults/secrets/get` (data plane) | `Microsoft.Storage/storageAccounts/listkeys/action` + subsequent `SharedKey` blob GET |
| `eventName = GetObject` (credential-file pattern) | (analogous — `sites/config` returns app_settings blob) | (retrieved via KV data plane API) | Storage diagnostic: `GET` blob with `AuthenticationType = "AccountKey"` |
| Content pattern in response (e.g. `AWS_SECRET`) | `application_id` + `client_secret` keys in JSON response | Secret metadata + value in response | JSON structure with `azuread_application.attributes.client_secret` |
| First-use event: `sts:GetCallerIdentity` with novel key ID | AAD SignInLogs `NonInteractiveUserSignIn` with new `AppId` | AAD SignInLogs `NonInteractiveUserSignIn` with SP's `AppId` | Same as Z2/Z5 — AAD SignInLogs |
| Correlation dimension: IP + UA + time window | Correlation dimension: `CallerIpAddress` + `UserAgent` + AAD `CorrelationId` window | Correlation across two log sources: KV diagnostic + AAD SignInLogs | Correlation across three log sources: Activity Log + storage diagnostic + AAD SignInLogs |

## Asymmetries

### Asymmetry 1 — Surface diversity (Azure exercises 3, AWS exercises 2)

AWS has 2 credential-discovery paths in the catalogue (P7, P8) — Lambda env-var + S3 object. Azure has 3 paths (Z2, Z5, Z6) across three distinct storage classes: App Service config, Key Vault, Storage Account blob.

**Detection implication**: the Azure counterpart of this primitive splits into three query variants at implementation time. Each variant handles a different combination of read event source + credential first-use correlation. A defender treating all three as "the same" (as AWS does with P7/P8) will miss surface-specific patterns.

### Asymmetry 2 — Intended vs unintended storage semantics

Z5 exploits credentials in Key Vault, which is Microsoft's *recommended* storage location for secrets. Read events on Key Vault are baseline-normal traffic (production apps read secrets constantly). Detection cannot rely on "reading a secret is suspicious" — it must reason about *who* should read *which* vault.

AWS has no equivalent problem for P7/P8 because Lambda env-vars and S3 objects are *not* recommended storage for credentials — reads on credential-shaped content in those surfaces are already anomalous by policy.

**Detection implication**: Z5's baseline join is strictly harder than P7/P8's. Requires principal-vault-secret 3-tuple history, not just principal-file history. Documented in `paths.md` §Z5.

### Asymmetry 3 — Data-plane log defaults

Azure data-plane logs (Key Vault `AuditEvent` diagnostic, Storage `StorageRead` diagnostic) are **off by default**. Detection primitives referencing these surfaces silently fail on unconfigured storage accounts and vaults — an operator who has "detection primitive 04 deployed" may still be blind to Z5/Z6.

AWS CloudTrail captures the equivalent events (Lambda GetFunctionConfiguration, S3 GetObject with data events enabled) by default (though S3 data events also require explicit enablement, that's a well-known gap).

**Detection implication**: the Azure counterpart of primitive 04 must include a preflight check — "is diagnostic logging enabled on this KV / SA?" — before it can operate at all. This is a preventive-control gap, not a detection query gap, but it affects the primitive's real-world reliability.

### Asymmetry 4 — Storage Account shared-key bypass (D-Z6-01) ⭐

Z6's discovery mechanism has **no AWS analogue**.

- On AWS, S3 access always requires IAM authentication. The identity behind an `s3:GetObject` call is always visible in CloudTrail with a resolved principal ARN.
- On Azure, Storage Account access can use shared-key authentication (legacy compatibility). Once an identity retrieves an account key via `listKeys` (control plane), all subsequent blob operations authenticate as `AuthenticationType = "AccountKey"` — bypassing AAD, RBAC, and the identity resolution that AWS enforces.

This has three concrete detection consequences:

1. **RBAC audits miss the risk**. The `Storage Account Key Operator Service Role` grants only `listKeys` / `regenerateKey` actions — no data-plane RBAC. An identity with only this role appears "control-plane only, safe from data-plane concerns" in any static RBAC audit. But it holds full data-plane authority via the retrieved key. Documented as D-Z6-01.
2. **Two-log-source correlation required**. Detection needs both Activity Log (`listKeys` event) AND storage diagnostic (`SharedKey` blob access) correlated by IP/time to identify the specific caller. Neither log alone is sufficient.
3. **Diagnostic-off invisibility**. Storage diagnostic logs are off by default (see Asymmetry 3). Environments without this enabled have no visibility into SharedKey-authenticated blob access at all.

AWS's S3 architecture, which never supported shared-key auth, avoids this entire class of detection difficulty. This is documented as a comparative finding for thesis Section 4.

### Asymmetry 5 — First-use identity resolution

AWS: the first-use of a leaked access key is a `sts:GetCallerIdentity` or any AWS API call with the specific `AccessKeyId`. The key ID is a persistent, resolvable identifier — you can pattern-match on it directly.

Azure: the first-use of a leaked SP credential is an AAD SignInLog `NonInteractiveUserSignIn` event with the SP's `AppId`. But SP tokens are short-lived; each token acquisition is a separate SignIn event. Correlation across the leak event and the sign-in event uses `CorrelationId` (per-request) or `AppId` (per-SP identity).

**Detection implication**: AWS detection can key on access key ID persistence — the same ID appearing in a leak event and a use event is a strong signal. Azure detection has no equivalent stable identifier at the token level; must key on `AppId` + temporal correlation with the leak event, which produces more false positives (an SP might legitimately sign in shortly after any config read).

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 04 will:

1. **Split into three query variants** — one per surface (App Service config, Key Vault, Storage Account). Each variant references its specific event source and correlation window.
2. **Include a preflight check** — verify diagnostic logging is enabled on the relevant KV/SA before running the query. Emit a warning otherwise.
3. **Use `CorrelationId` + `AppId` for cross-log join** — not access-key-style persistent ID matching.
4. **Include Z6-specific dual-log correlation** — Activity Log `listKeys` events must be joined with storage diagnostic SharedKey blob GETs.
5. **Reference the primitive's Azure asymmetry catalogue** — three variants + D-Z6-01 finding + diagnostic-off preflight — as the primary structural argument that "same primitive, different implementation."

Primitive 04's design is validated as **partially cloud-invariant**. The high-level structure (credential-bearing read + correlated first-use) translates. The specific query, log source composition, and preventive control set are strictly cloud-specific and differ substantially between AWS and Azure.

## Coverage matrix (updated for verified paths)

| Path | Primary detection query type | Data-plane logging default | Baseline complexity |
|---|---|---|---|
| P7 | CloudTrail — GetFunctionConfiguration + STS first-use | On (CloudTrail default) | Low (principal-file history) |
| P8 | CloudTrail — GetObject with credential-file pattern | On (CloudTrail default, S3 data events explicit) | Low-Medium |
| Z2 | Activity Log — sites/config/list + AAD SignIn correlation | On (Activity Log default) | Medium (principal-webapp history) |
| Z5 | KV diagnostic — secrets/get + AAD SignIn correlation | **Off by default** | High (principal-vault-secret 3-tuple history) |
| Z6 | Activity Log — listKeys + storage diagnostic SharedKey GET + AAD SignIn | **Off by default (both storage diagnostic + Activity Log for the correlation)** | High + bypasses AAD identity resolution |

Complexity trend: Azure paths (Z2, Z5, Z6) generally require more baseline dimensions and more log sources than AWS paths (P7, P8) for equivalent detection confidence. This is a consistent pattern across the primitive.
