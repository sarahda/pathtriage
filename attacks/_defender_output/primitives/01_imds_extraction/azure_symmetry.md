# Primitive 01 — AWS↔Azure Signal Correspondence

## Purpose

Sanity check that primitive 01's detection concept is expressible in Azure. Confirms cross-cloud validity without duplicating the W8 Azure-KQL implementation work.

## Signal Correspondence

The AWS primitive detects: **an ASIA-prefixed session credential issued to an EC2 instance role, subsequently used from a network location or user agent that does not match the issuing instance's metadata**.

The Azure equivalent detects: **a Managed Identity token issued via IMDS to a specific VM, subsequently used from a caller identity or IP that doesn't match the VM's expected origin**.

The primitive is cloud-invariant at the abstract level:
Compute-attached identity credential
→ observed in control-plane logs (CloudTrail STS / Azure Activity)
→ correlated with source binding metadata
→ fires when the binding is violated

## Azure paths covered

Two verified Azure paths exercise this primitive through different access patterns:

- **Z1** — VM's own MI token exfiltrated and used off-VM (single-VM primitive)
- **Z8** — Attacker uses runCommand on VM-B to run code that reads VM-B's IMDS and returns MI-B token via response body (**cross-VM primitive** — attacker never has direct SSH access to the target VM)

Same primitive class (IMDS token extraction + off-source use), but different access mechanic. Z1 is single-host; Z8 is cross-VM via control-plane compute action. Detection queries need to handle both.

## AWS log surface → Azure log surface mapping

| AWS field | Azure equivalent (Z1) | Azure equivalent (Z8) |
|---|---|---|
| `sourceIPAddress` on API call | `callerIpAddress` in Azure Activity Log | `callerIpAddress` on the runCommand event (attacker's IP on VM-A) + subsequent MI token use from potentially different IP |
| `userAgent` | `userAgent` in Azure Activity Log | Same |
| `userIdentity.arn` (assumed-role session ARN) | `identity.tokenClaims.oid` or MI principal ID | `identity.tokenClaims.oid` — but token is issued to VM-B, used elsewhere |
| Instance metadata: `ec2:DescribeInstances` for source binding | `Microsoft.Compute/virtualMachines/read` for VM-to-MI binding | Same, plus: correlate runCommand caller identity with the MI principal ID it retrieved |
| CloudTrail `resources[].ARN` matching instance profile | Azure Activity Log `resourceId` matching VM ID | Two resourceIds: the runCommand source VM (VM-A) and the MI's associated VM (VM-B) |
| Off-instance use detection: source IP not in the instance's VPC ENI range | Off-VM use detection: `callerIpAddress` not in the VM's VNet address space (via VNet metadata lookup) | Off-VM use detection: MI-B token used from a caller IP that doesn't match VM-B's network interface **AND** was preceded by a runCommand event by a different identity |

## Asymmetries

### Asymmetry 1 — Token lifetime differs materially

AWS STS credentials for EC2 instance roles default to **1 hour** (adjustable via role max session duration, up to 12 hours).

Azure MI tokens returned from IMDS default to **~24 hours** and cannot be shortened by the calling application.

**Detection implication**: an exfiltrated MI token has a materially larger blast radius than an exfiltrated AWS session credential. The Azure detection window for token use must extend up to 24 hours; the AWS window is bounded by 1-hour default sessions. This affects the primitive's `:token_use_window_hours` parameter in the Azure counterpart.

### Asymmetry 2 — Instance-to-role binding is one-to-many in AWS, one-to-one in Azure

An AWS EC2 instance profile can wrap one IAM role; but one IAM role can be attached to many EC2 instance profiles across many instances. Detection must correlate the specific issuing instance to the specific credential.

An Azure System-Assigned MI is inherently one-to-one with its host VM — the MI's `principalId` and `objectId` are unique to that VM. User-Assigned MIs can be shared across VMs (one-to-many), which is used in Z7 but not Z1.

**Detection implication**: for Z1 (System-Assigned MI), the MI principal ID directly identifies the source VM — no ambiguity. For AWS, the STS credential's `sourceIdentity` claim or the CloudTrail request context must be joined with instance profile inventory. Azure primitive is simpler in the System-Assigned MI case; matches AWS complexity in the User-Assigned case.

### Asymmetry 3 — Cross-VM IMDS access via runCommand (Z8) ⭐

**AWS has no direct equivalent** to Azure's `runCommand` primitive as an IMDS extraction mechanic.

- Azure Z8: Attacker's identity (MI-A) has narrow `runCommand` permission on VM-B. Attacker doesn't need SSH access to VM-B. Runs `runCommand` with a bash script that reads VM-B's local IMDS and echoes the token to stdout. Response body returns to attacker.
- AWS analogue: closest is `ssm:SendCommand` on an existing EC2 instance with SSM agent — but SSM requires IAM permission on the instance PLUS agent installed PLUS specific SSM permissions on the identity. It's a narrower and more visible attack surface.

**Detection implication**: primitive 01 on Azure must include cross-VM correlation:

- runCommand event on VM-B with identity X (from Activity Log)
- Subsequent MI-B token use, potentially from an IP not matching VM-B's network interface
- Where identity X's baseline does not include IMDS-related runCommand usage against VM-B

The AWS primitive does not need this cross-VM correlation because remote code execution against another instance's IMDS via IAM alone is not a native primitive.

Documented in D-Z8-02 (runCommand response envelope permits in-band token exfiltration). This is the primary Z8 contribution to primitive 01's cross-cloud characterization.

### Asymmetry 4 — IMDS response format and access mechanic

AWS IMDSv1: HTTP GET on `169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}` returns JSON with credentials. Anyone with network access to the metadata endpoint (including SSRF-reachable) gets credentials.

Azure IMDS: HTTP GET on `169.254.169.254/metadata/identity/oauth2/token` requires `Metadata: true` header (not sent by browsers by default) AND a `resource` parameter. Response is OAuth2 token JSON. This makes casual SSRF less exploitable — but any local process with network access can query IMDS trivially.

**Detection implication**: Azure IMDS SSRF attacks (equivalent to AWS Path 2) require a specific header manipulation, so pure SSRF payloads that work on AWS often fail on Azure IMDS. This makes Z1-style attacks less accessible via web SSRF, but equally accessible via local code execution (Z1, Z8) or credential leakage that leads to local exec (Z2, Z5, Z6).

The primitive detection is unchanged — the attack surface is narrower on Azure, but detection semantics are the same.

## Design implications for W8 Azure primitive

The W8 Azure counterpart of primitive 01 will:

1. Reference Azure Activity Log as the primary event source for both the credential issuance context (VM `read` operations, MI operations) and use context.
2. Correlate against VM inventory via `Microsoft.Compute/virtualMachines` metadata to establish the MI-to-VM binding.
3. **Include cross-VM correlation for Z8-style attacks**: runCommand events on any VM must be joined with subsequent MI token usage from potentially unrelated networks. This is unique to Azure.
4. Use `callerIpAddress` + `userAgent` as source binding checks — Azure Activity Log includes both, matching CloudTrail's model.
5. Handle User-Assigned MI (shared identity) case by falling back to per-request `oid` claim analysis, matching AWS's approach when instance profiles are shared.

Primitive 01's design is validated as broadly cloud-invariant, with two structural differences that require Azure-specific handling: the cross-VM runCommand vector (Z8) and the extended token lifetime. These are documented and will be visible in the W8 Azure query as distinct query variants.

## Coverage matrix (updated for verified paths)

| Path | Access mechanic | Detection focus | Token lifetime |
|---|---|---|---|
| P1 (AWS) | Instance role via IMDS on same instance | STS credential + source IP + instance binding | 1h default |
| P2 (AWS) | SSRF → IMDS on same instance | Same as P1 + SSRF pattern | 1h |
| P6 (AWS) | Instance profile abuse from existing foothold | Same as P1 | 1h |
| Z1 (Azure) | System-Assigned MI via local IMDS | MI token + callerIpAddress + VM binding | ~24h |
| Z8 (Azure) | Cross-VM via runCommand + remote IMDS read | Two-source correlation: runCommand event + subsequent MI token use | ~24h |

Coverage asymmetry: AWS covers 3 paths with a shared detection template (all same-VM IMDS extraction). Azure covers 2 paths but one (Z8) requires materially different detection logic (cross-VM). The primitive's Azure implementation must include this variant to have complete coverage.
