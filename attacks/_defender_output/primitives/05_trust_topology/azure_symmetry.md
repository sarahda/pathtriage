# Primitive 05 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 05's detection concept is expressible in Azure. Confirms cross-cloud validity without duplicating W8 Azure-KQL implementation.

## Signal Correspondence

The AWS primitive detects: **multi-hop `sts:AssumeRole` chains from a starting principal to a terminal role, where the chain or terminal is novel for the principal**.

The Azure equivalent detects: **cross-identity impersonation or role-assignment chains where a starting Managed Identity or Service Principal reaches a new terminal identity via intermediate delegations**.

Cloud-invariant primitive structure:

```
Cross-identity traversal event
    → observed in control-plane logs (CloudTrail STS / Azure Activity + AAD)
    → chain reconstruction across time window
    → correlated with historical chain baseline for starting principal
    → fires on chain length + novelty + terminal privilege
```

## Azure paths covered

- **Z7** — Managed Identity / Service Principal chain: MI assigns role to a second identity, or one MI impersonates another via delegated authority. Direct analogue of P4. Not yet verified (W7-W8 planned).

## AWS log surface → Azure log surface mapping

Azure lacks a direct equivalent of AWS's `sts:AssumeRole` — Azure identities do not "assume" other identities in the same session-generating way. The Azure analogue is a **combination of two mechanisms**:

- **Role assignment**: `Microsoft.Authorization/roleAssignments/write` binds a principal to a scope with a role. If MI-A assigns MI-B to admin scope, MI-B can then act with admin. Detected by primitive 02 and analysed in `../02_iam_mod_assign/azure_symmetry.md`.
- **On-Behalf-Of (OBO) token flow**: an SP with delegated permission requests a token on behalf of another identity via OAuth 2.0 OBO flow. This is the closer analogue of AssumeRole for chained access.

The Azure trust-topology detection therefore involves both surfaces:

| AWS field | Azure equivalent | Notes |
|---|---|---|
| CloudTrail `eventName = AssumeRole` | AAD SignInLogs OAuth 2.0 On-Behalf-Of token events | Direct analogue for OBO flow |
| CloudTrail `userIdentity.arn` (caller) | AAD SignInLogs `UserPrincipalName` / `ServicePrincipalName` | Starting identity |
| CloudTrail `requestParameters.roleArn` (target) | AAD SignInLogs `AppId` / target resource | Target identity or resource |
| CloudTrail `responseElements.assumedRoleUser.arn` | AAD SignInLogs `AppId` of the target | Assumed identity |
| Chain reconstruction via self-join | AAD SignInLogs `CorrelationId` join across events | Correlation IDs group related sign-ins |

## Asymmetries

### Asymmetry 1 — No native chained impersonation

AWS AssumeRole is designed for identity chaining; a role can trust another role which can trust another. Chain length is bounded by policy but semantically unlimited.

Azure does not have direct chained impersonation. The closest is OBO flow, which requires explicit configuration (client credentials + delegated permissions grant + user consent). Multi-hop OBO is unusual and requires each intermediate SP to be configured.

**Detection implication**: Azure trust-chain attacks are structurally rarer. Primitive 05's Azure counterpart focuses on the **role assignment cascade** — MI-A → assigns MI-B → uses MI-B → uses MI-B's authority — rather than pure OBO chains. The detection signal is a burst of role assignment writes from the same MI followed by immediate token acquisitions by the newly-empowered MIs.

### Asymmetry 2 — Session-level vs authorization-level chain

AWS chain traversal is session-level: each AssumeRole creates a new session with its own temporary credentials. The chain is directly visible in CloudTrail as a sequence of AssumeRole events.

Azure role assignment is authorization-level: the target MI gains permissions permanently until the assignment is removed. The token acquisition afterward is a separate event and might occur hours or days later.

**Detection implication**: Azure chain detection has a longer natural correlation window (chain "hops" can span days if the attacker uses the granted permissions sporadically). The primitive's `:chain_window_min` parameter is not directly transferable; Azure needs a two-phase detection — role assignment event, then subsequent token/action correlation over longer windows.

### Asymmetry 3 — MFA propagation

AWS `AssumeRole` can propagate MFA context via session tags but does not enforce MFA on chained hops by default. Requires explicit trust policy conditions.

Azure OBO tokens do not propagate MFA at all — MFA is per-user, not per-token. Chained access from an SP inherently lacks MFA context.

**Detection implication**: primitive 05's `DenyAssumeAdminRoleWithoutMFA` SCP (see `scp_snippet.json`) has no Azure equivalent. Azure trust-chain prevention relies on Conditional Access policies, which operate at authentication time, not at role-use time. Detection carries more weight on Azure.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 05 will:

1. Focus on **role assignment cascades** rather than session-chain reconstruction. Query: for each MI/SP that performs `roleAssignments/write` on another MI/SP, look for the recipient's subsequent token usage within an extended window (up to 24 hours).
2. Use AAD `CorrelationId` to group related sign-in events instead of self-joining AssumeRole events.
3. Include both delegation flows: (a) role assignment cascade (detected by primitive 02 + follow-up), and (b) OBO token flow (detected by primitive 05's Azure equivalent).
4. Note that MFA cannot be assumed on any chained access — Conditional Access policies at authentication time are the primary preventive control.

Primitive 05's design is validated as **partially cloud-invariant**. The structure (chain reconstruction + novelty baseline) translates. The specific correlation mechanism (self-join on AssumeRole) does not — Azure uses correlation IDs and asynchronous permission activation. The Azure primitive will look different in implementation while serving the same detection concept.

This is the largest structural difference among the five primitives' cross-cloud mappings. Documented in the module's aggregate azure-symmetry summary in `../../README.md` (planned final section) as an example of where cloud-invariant primitive design has genuine limits.
