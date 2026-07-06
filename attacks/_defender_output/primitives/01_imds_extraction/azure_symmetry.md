# Primitive 01 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 01's detection concept is expressible in Azure. Confirms cross-cloud validity of the primitive design without duplicating the W8 Azure-KQL implementation.

## Signal Correspondence

The AWS primitive detects: **use of EC2-instance-role temporary credentials from a source location inconsistent with the issuing instance's historical egress**.

The Azure equivalent detects: **use of a VM Managed Identity token from a source location inconsistent with the issuing VM's historical egress**.

Cloud-invariant primitive structure:

```
Compute-instance identity (MI/instance role)
    → issues short-lived credentials
    → observed in control-plane logs (Activity/CloudTrail)
    → correlated with issuing-instance historical egress baseline
    → fires on spatial mismatch
```

## Azure paths covered

- **Z1** — VM Managed Identity via IMDS: MI token used from off-box. Direct analogue of P6.
- **Z8** — VM Run Command abuse: attacker uses `virtualMachines/runCommand/action` to execute as MI. The subsequent MI token use fires primitive 01's Azure counterpart.

Not covered by primitive 01: pure Azure paths that don't involve IMDS (Z2 SP credential theft — cred discovery primitive; Z3/Z4 IAM mod primitives; Z5/Z6 credential discovery; Z7 trust topology).

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent | Notes |
|---|---|---|
| CloudTrail `userIdentity.type = "AssumedRole"` | AzureActivity `Caller` = MI object ID | Azure MI tokens carry `oid` claim, surfaces as `Caller` in Activity Log |
| CloudTrail session name `i-<id>` | AzureActivity token `xms_mirid` claim (MI resource ID) | Azure encodes the issuing VM in the token itself |
| CloudTrail `sourceIPAddress` | AzureActivity `CallerIpAddress` | Direct equivalent |
| CloudTrail `userAgent` | AzureActivity `UserAgent` | Direct equivalent |
| Historical instance egress (from `DescribeInstances`) | Historical VM egress (from `AzureNetworkAnalytics_CL`) | Requires Network Watcher/Flow Logs enabled; not default |

The main structural difference is that Azure's Managed Identity token includes the issuing-VM resource ID in the JWT itself (`xms_mirid` claim), while AWS embeds it in the session name. Both provide the same correlation anchor for the baseline join.

## Asymmetries

### Asymmetry 1 — Token binding vs credential propagation (D-Z4-03 pattern)

AWS STS temporary credentials propagate IAM changes near-immediately: if a role is modified, in-flight credentials reflect the change on their next API call (short eventual consistency).

Azure MI tokens are bound to the permissions established at token issuance. A permission change requires the caller to acquire a fresh token before the new permissions apply. Documented in the Z4 README (D-Z4-03).

**Detection implication**: on Azure, a follow-up "fresh IMDS token immediately after a control-plane change on the same MI" is a strong corroborating signal — the Azure equivalent of "MTTD approaches zero if you correlate token issuance with subsequent write." The AWS primitive does not need this correlation because the credentials propagate; the Azure primitive can exploit it for a tighter signal.

The AWS primitive 01 does not model this asymmetry. The Azure counterpart (built in W8) is expected to include a token-refresh-after-mutation sub-signal.

### Asymmetry 2 — IMDSv1 vs IMDSv2 vs Azure IMDS

AWS distinguishes IMDSv1 (unauthenticated) from IMDSv2 (token-required). SCP-level IMDSv1 denial (see `scp_snippet.json`) closes SSRF-to-credential paths.

Azure IMDS has no v1/v2 distinction. The `Metadata: true` header requirement is the sole guard, and it is default-enforced but browser-reachable (any HTTP client can set the header). Azure Policy can prevent VM creation without private-only IMDS access, but IMDS itself has no token-based version.

**Detection implication**: SSRF-to-IMDS is structurally easier to exploit on Azure than AWS post-IMDSv2. The Azure primitive counterpart must lean more heavily on runtime detection because prevention is weaker.

### Asymmetry 3 — Cross-tenant token use

Azure MI tokens can, in principle, be sent to any Azure AD tenant's endpoints if the SDK URL is overridden. Real-world detection assumes tokens are only used against `management.azure.com`, but Azure Policy does not enforce this.

AWS STS credentials cannot cross-account without explicit trust (governed by the `sts:AssumeRole` trust policy). AWS's boundary is stronger by construction.

**Detection implication**: no direct impact on primitive 01, but relevant to the Azure trust-topology primitive (05 equivalent in W8).

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 01 will:

1. Extend the baseline-join to include `xms_mirid` claim as the instance-anchor.
2. Add the token-issuance ↔ subsequent-write correlation as a stronger sub-signal.
3. Document that IMDS access from within the VM is un-preventable at the network layer (unlike AWS IMDSv2 SCP), so runtime detection is the primary defence.
4. Reuse the AWS query's structural approach (candidate → baseline join → anomaly flag → fire) with Azure Sentinel KQL syntax.

Primitive 01's design is thereby validated as cloud-invariant modulo the three asymmetries above. The detection concept transfers; the implementation details differ.
