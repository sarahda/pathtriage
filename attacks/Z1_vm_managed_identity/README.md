# Z1 — VM Managed Identity via IMDS

| Field | Value |
|---|---|
| Class | Compute / IMDS |
| Primary primitive | IMDS read with overprivileged System-Assigned MI |
| MITRE ATT&CK | T1552.005 (Cloud Instance Metadata API) |
| AWS analogue | Path 6 (EC2 Instance Profile Abuse) |
| Cred type | OAuth2 Bearer token (ARM-scoped) |
| Token lifetime | ~24h (vs ~1h for AWS STS) |

## Setup

A Linux VM in `pathtriage-rg` has a System-Assigned Managed Identity
that has been granted `Contributor` at subscription scope. The
misconfiguration is the over-broad role assignment — `Contributor`
should never be granted at subscription scope to a single VM's MI.

## Attack flow

1. Attacker has SSH access to the VM (assumed prior foothold)
2. From inside the VM, attacker queries IMDS:
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H 'Metadata: true'
3. IMDS returns a Bearer token scoped to ARM, bound to the VM's MI
4. Attacker exfiltrates the token and uses it from their own host:
   - Lists subscriptions (Reader+)
   - Lists all VMs in subscription (Contributor)
   - Inspects MI's role assignments (proves admin scope)

## Defender implications

**Detection (Sentinel KQL primitive):** The detectable signature is an
ARM API call authenticated as the VM's MI from a source IP that does
not match the VM's network interface. This is the Azure analogue of the
AWS off-box-token-use primitive — and Z1, Z6 (Run Command), and Z8 are
expected to converge onto the same primitive.

**Remediation (Azure Policy):** Deny role assignments at subscription
scope whose principal is a VM's System-Assigned MI. Scope MI permissions
to the resource level only, or use User-Assigned MIs with explicit
scope review.

## Verification criterion

`verification_log.txt` must show:
- Token successfully extracted from IMDS
- Token grants access to subscription-scope VM list
- Token's role assignments confirm Contributor at subscription scope