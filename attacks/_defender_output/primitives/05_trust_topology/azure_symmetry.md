# Primitive 05 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 05's detection concept is expressible in Azure. Confirms cross-cloud validity — with the important qualification that the Azure implementation is **structurally different** from the AWS implementation due to a discovered platform-level asymmetry (D-Z7-02).

## Signal Correspondence

The AWS primitive detects: **multi-hop `sts:AssumeRole` chains from a starting principal to a terminal role, where the chain or terminal is novel for the principal**.

The Azure equivalent detects: **role assignment cascade — one identity creates a role assignment binding another attacker-controlled identity to broader authority, followed by the newly-granted identity performing the elevated action**.

Cloud-invariant primitive structure at the abstract level:

```
Cross-identity privilege delegation event
    → observed in control-plane logs
    → correlated with subsequent action by the recipient identity
    → fires when the delegation crosses identity boundaries and
      the recipient's post-delegation authority differs from its
      pre-delegation authority
```

But the concrete mechanic differs fundamentally between clouds. This primitive has the largest structural cross-cloud difference in the catalogue.

## Azure paths covered

- **Z7** — Managed Identity / Service Principal chain via role assignment cascade

Only one path in the primitive on the Azure side. Not because trust topology is rare in Azure, but because the direct semantic analogue of AWS `sts:AssumeRole` chained impersonation is **structurally blocked** by the Azure identity platform (see Asymmetry 1 below).

## D-Z7-02 — Azure OBO structurally blocks pure SP-to-SP chained impersonation ⭐

The originally-planned Z7 design was OAuth 2.0 On-Behalf-Of (OBO) flow as the direct semantic equivalent of `sts:AssumeRole`. Attacker's Service Principal A would obtain an initial token, then perform OBO token exchange to obtain a token acting as Service Principal B.

Azure returned `AADSTS500131`:

> "Assertion audience does not match the Client app presenting the assertion. The audience in the assertion was 'SP-B-app-id' and the expected audience is 'SP-A-app-id' or one of the Application Uris of this application."

**Root cause**: Azure OBO requires the initial assertion token to have `aud=SP-A` (the app presenting the OBO request). This audience only exists in **user delegation flows** — when a user signs in to SP-A via UI or MFA, the resulting token has `aud=SP-A`. Pure `client_credentials` flow cannot produce a self-audience token; Azure explicitly refuses to issue such tokens.

**Structural consequence**: Azure prevents pure SP-to-SP chained impersonation at the identity platform level. AWS `sts:AssumeRole` has no equivalent user-delegation requirement — any principal (user or role) can chain-assume any role whose trust policy permits it, purely programmatically. This is a **structural asymmetry**: AWS P4's attack surface (pure programmatic identity chaining) does not exist in Azure at all.

**Resolution**: Z7 pivoted to role-assignment cascade as the closest available Azure primitive. This changes the semantic:

- AWS session-chain: "SP-A becomes SP-B" (transient session, credentials swap)
- Azure cascade: "SP-A grants authority to SP-B, then SP-B acts" (persistent authorization, no credential swap)

Both are trust-topology attacks, but the mechanics — and therefore the detection surfaces — differ substantially.

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent (Z7 cascade) |
|---|---|
| CloudTrail `eventName = AssumeRole` (single event) | Two separate events: `Microsoft.Authorization/roleAssignments/write` (Activity Log) + subsequent AAD SignIn by the granted identity |
| `userIdentity.arn` (caller of AssumeRole) | Activity Log `caller` on the `roleAssignments/write` event |
| `requestParameters.roleArn` (target role assumed) | `principalId` in the role assignment request body |
| `responseElements.assumedRoleUser.arn` | AAD SignIn `AppId` of the newly-granted identity in the subsequent sign-in |
| Chain reconstruction: 3+ AssumeRole events with matching principal sequence | Correlation: `roleAssignments/write` where `principalId != caller` + subsequent AAD SignIn by that principalId |
| Time window: `chain_window_min` (default 15 min) | Time window: `propagation + use window` (default 5-30 min — see Asymmetry 3) |

## Asymmetries

### Asymmetry 1 — No native chained impersonation (D-Z7-02) ⭐

Documented in detail above. AWS provides `sts:AssumeRole` chaining as a first-class primitive — a role can trust another role which can trust another, with no user involvement. Chain length is bounded by session policy but semantically unlimited.

Azure does not provide direct chained impersonation between Service Principals in the programmatic path. The closest is OBO flow, which requires:
- Explicit delegated permission configuration on both SPs
- User consent (or admin consent) on the delegation
- A user-audience token as the OBO assertion (only obtainable via user sign-in)

Multi-hop OBO is possible in theory (each SP could in principle OBO to the next) but requires user-delegation credentials to survive across hops, which is not the pure-programmatic chain that AWS supports.

**Detection implication**: Azure trust-chain attacks manifest through a fundamentally different mechanic — role assignment cascade rather than session chaining. The AWS primitive's self-join chain reconstruction has no Azure counterpart.

### Asymmetry 2 — Session-level vs authorization-level chain

AWS chain traversal is **session-level**: each `AssumeRole` creates a new session with its own temporary credentials. The chain is directly visible in CloudTrail as a sequence of AssumeRole events. Session credentials expire (typically 1 hour) and the chain is transient.

Azure role assignment is **authorization-level**: the target identity gains permissions persistently until the assignment is removed. The subsequent token acquisition is a separate event and might occur hours, days, or weeks later.

**Detection implication**: Azure chain detection has a longer natural correlation window and requires cross-log-source join. The AWS primitive's `:chain_window_min = 15` parameter is not directly transferable — Azure needs a two-phase detection:

1. `roleAssignments/write` event where `principalId != caller` (the cascade grant)
2. Subsequent AAD SignIn by the granted `principalId` at any time within a longer window (default 30 min for tight detection, up to 24 hours for post-facto analysis)

Longer windows increase FP risk; the tradeoff differs from AWS entirely.

### Asymmetry 3 — Propagation gap between grant and use (D-Z7-03)

Azure role assignments created via `roleAssignments/write` return HTTP 201 immediately, but require 30-60 seconds for propagation to the token validation layer. During this window, the granted identity cannot yet use its new authority.

**Detection implication**: this propagation gap is itself a detection signal window. A `roleAssignments/write` event where `principalId != caller`, followed by a token acquisition by the granted identity within the propagation window (attempting to use before Azure has propagated), is a highly suspicious pattern — legitimate operators typically don't attempt immediate token use post-grant.

AWS `sts:AssumeRole` has no equivalent propagation gap. STS credentials work immediately upon return. This detection signal has no AWS analogue.

### Asymmetry 4 — MFA propagation

AWS `sts:AssumeRole` can propagate MFA context via session tags. Chained AssumeRole can require MFA at each hop via trust policy conditions.

Azure OBO tokens do not propagate MFA at all — MFA is per-user at authentication time, not per-token. Role assignment cascades from an SP inherently carry no MFA context.

**Detection implication**: primitive 05's AWS SCP preventive control (`DenyAssumeAdminRoleWithoutMFA`) has no direct Azure equivalent. Azure trust-chain prevention relies on:

- Conditional Access policies (operate at authentication time, not at grant time)
- Custom deny policies on `roleAssignments/write` (limited by Azure Policy engine expressiveness)
- Just-in-time privileged access (PIM) — separate feature, not applicable to SP-to-SP flows

Detection carries proportionally more weight on Azure because preventive controls are weaker.

### Asymmetry 5 — Persistent vs ephemeral escalation

AWS P4's escalation persists only for the STS session duration (default 1 hour). Attack detection or investigation can leverage session expiry — the malicious credential set will vanish naturally within one hour.

Azure Z7's role assignment persists until explicitly deleted. Once SP-A grants Contributor to SP-B, the grant survives across sessions, credential rotations, and even SP-A's compromise being remediated. Detection is time-critical: if the role assignment is not detected and reversed, SP-B retains authority indefinitely.

**Detection implication**: Azure trust-topology attacks require faster mean-time-to-detect (MTTD) than AWS equivalents. MTTD > 1 hour on AWS = attack window closes naturally; MTTD > 1 hour on Azure = attacker has persistent authority. The Azure primitive should be tuned for aggressive early-detection settings, accepting higher FP rate.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 05 will:

1. **Not include OBO detection** — D-Z7-02 shows this attack class is structurally blocked, so no detection is needed for pure SP-to-SP OBO chains.
2. **Focus on role assignment cascades** — query pattern: `roleAssignments/write` where `principalId != caller` + subsequent AAD SignIn by that principal within a configurable window (short: 5 min for high-confidence; long: 24 hours for post-facto).
3. **Include propagation-gap detection** — token use attempts during the 30-60s propagation window post-grant are anomalous even for legitimate operators.
4. **Use two-log-source correlation** — Activity Log for the grant, AAD SignInLogs for the use, joined by `principalId`.
5. **Accept longer natural correlation windows** — Azure's authorization-level chain is not session-bounded, so windows extend to days for comprehensive coverage.
6. **Note the preventive weakness** — MFA/CA don't cover SP-to-SP flows, so detection is the primary defense.

Primitive 05's design is validated as **cloud-invariant only at the abstract level**. The concrete mechanic, query structure, log sources, and time windows all differ substantially. This is the largest structural difference among the five primitives.

The finding itself — that Azure structurally blocks one attack class (pure SP-to-SP OBO chain) while permitting another (persistent role cascade) — is the primary trust-topology contribution to thesis Section 4.

## Coverage matrix (updated for verified paths)

| Path | Primary detection query type | Correlation dimensions | Preventive control availability |
|---|---|---|---|
| P4 (AWS) | CloudTrail self-join on AssumeRole chain | Principal + time window (15 min) | SCP + trust policy conditions + MFA gates |
| Z7 (Azure) | Activity Log (`roleAssignments/write` where `principalId != caller`) + AAD SignInLogs (subsequent SignIn by that principal) | Two log sources + `principalId` cross-join + longer time window (5-30 min tight, up to 24h post-facto) | Weak: Conditional Access doesn't cover SP-to-SP flows, PIM doesn't apply |

Coverage asymmetry: AWS P4 is detectable via a single log source with tight temporal correlation. Azure Z7 requires two log sources with longer temporal windows and has weaker preventive control options. Detection carries more weight on Azure because prevention is limited.
