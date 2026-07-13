# Z8 — VM Run Command Abuse

## Overview

Two VMs in the same resource group. **VM-A** hosts the attacker's foothold via a compromised Managed Identity (**MI-A**). **VM-B** hosts an elevated Managed Identity (**MI-B**) with subscription-level Contributor scope.

MI-A holds a custom role on VM-B called `VM Diagnostic Runner` that grants only two actions: `virtualMachines/read` and `virtualMachines/runCommand/action`. The role name and scope suggest "diagnostic access to one VM" — but `runCommand` permits arbitrary shell execution as root/SYSTEM. The attacker uses `runCommand` to run a script on VM-B that reads MI-B's ARM token from local IMDS, then exfiltrates that token via the `runCommand` response body.

The starting privilege — a two-action custom role on one specific VM — is minimal by any RBAC audit. The escalation is not visible at the permission surface; it emerges from the semantic gap between "diagnostic runner" and "arbitrary root code execution".

## Attack Flow

```
┌───────────────────────────────────────────────────────────────┐
│  VM-A (attacker's foothold)                                   │
│    System-Assigned MI-A                                       │
│    RBAC: "VM Diagnostic Runner" (custom role) on VM-B only    │
│    Actions: virtualMachines/read, runCommand/action           │
└─────────┬─────────────────────────────────────────────────────┘
          │  ① IMDS → MI-A ARM token
          │  ② POST runCommand to VM-B with script:
          │
          │      curl 169.254.169.254 → MI-B token
          │      echo "===MI_B_TOKEN_BEGIN==="
          │      echo "$TOKEN"
          │      echo "===MI_B_TOKEN_END==="
          │
          │      (script runs as root on VM-B)
          ▼
┌───────────────────────────────────────────────────────────────┐
│  VM-B (target)                                                │
│    System-Assigned MI-B                                       │
│    RBAC: Contributor at subscription scope                    │
│                                                                │
│    ③ script executes as root on VM-B                          │
│    ④ VM-B local IMDS → MI-B ARM token                         │
│    ⑤ token echoed to stdout, captured by runCommand response  │
└─────────┬─────────────────────────────────────────────────────┘
          │  ⑥ runCommand response body includes MI-B token
          ▼
┌───────────────────────────────────────────────────────────────┐
│  Attacker (back on VM-A, or anywhere)                         │
│    parses response for MI_B_TOKEN markers                     │
│    extracts MI-B token (~1800 chars, fits within 4KB output)  │
└─────────┬─────────────────────────────────────────────────────┘
          │  ⑦ MI-B ARM token in hand
          ▼
┌───────────────────────────────────────────────────────────────┐
│  ARM (control plane) — as MI-B                                │
│    PATCH /subscriptions/{sub}/resourceGroups/{rg}/            │
│          providers/Microsoft.Resources/tags/default           │
│    permission: Contributor at sub scope ✓ (via MI-B)          │
│    result: RG tag write succeeds                              │
└───────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

- **T1651** — Cloud Administration Command (VM Run Command as the primary technique)
- **T1550.001** — Use Alternate Authentication Material: Application Access Token (MI-B's token as alternate credential)
- **T1078.004** — Valid Accounts: Cloud Accounts (MI-B as second-stage identity)
- AWS analogue: **P1** (PassRole + RunInstances) — same primitive class (compute hijack), same attack shape (narrow compute-related action escalates to code execution with a broader identity's authority).

## Prerequisites

- Azure baseline deployed (`environments/baseline_azure_personal/`)
- Personal MSA subscription (D-Z2-01)
- `~/.ssh/id_rsa.pub` present (RSA only per D-Z4-04)
- `az` CLI logged in with permission to create custom role definitions at RG scope + assign roles
- Deployer holds Owner (or Contributor + User Access Administrator) at subscription scope

## Vulnerable Configuration

Three design decisions produce the vulnerability:

1. **Custom role with `runCommand` action framed as "diagnostic"**. Custom roles are frequently created with well-intentioned but insufficient understanding. A role called "VM Diagnostic Runner" suggests limited access, but `Microsoft.Compute/virtualMachines/runCommand/action` grants root/SYSTEM shell execution — completely unbounded within the guest OS. This is a semantic gap between action name and effect.
2. **VM-B's MI holds Contributor at subscription scope**. A common pattern: automation VMs, CI/CD runners, or Bastion hosts are assigned broad authority for operational convenience. Once code executes on such a VM as root, that authority is fully accessible via local IMDS.
3. **No preventive gate on runCommand output content**. The `runCommand` response returns stdout/stderr up to ~4KB. Azure MI tokens (~1800 chars) fit easily. There is no default control that scans response bodies for secret patterns.

## Engineering Decision Log

### D-Z8-01: `runCommand` is asynchronous and requires polling

**Observation.** The initial POST to `/virtualMachines/{name}/runCommand` returns HTTP 202 with an `Azure-AsyncOperation` header, not the command output. Azure Compute runs the script as an async operation that typically takes 30-90 seconds to complete (first execution longer due to extension provisioning).

**Resolution.** The exploit polls the operation URL every 10 seconds up to 180 seconds default (configurable via `--poll-timeout`). Terminal states: `Succeeded`, `Failed`, `Canceled`. Once succeeded, the response body contains `properties.output.value[].message` with concatenated stdout/stderr.

**Implication for detection.** Two Activity Log events per attack: (1) the POST (permission check on MI-A), and (2) an implicit execution completion (not always logged separately by default). The gap between POST and completion is a signal window — an attacker script pattern is visible in the request body if the diagnostic log is enabled.

### D-Z8-02: `runCommand` response envelope permits ~4KB stdout — sufficient for token exfil

**Measurement.** The Azure Compute runCommand API returns stdout+stderr concatenated in `properties.output.value[0].message`, with an observed practical limit of approximately 4KB. Azure MI tokens are 1800-2000 characters, well within envelope.

**Implication.** Token exfiltration via runCommand response is straightforward — no need for external network channels from VM-B. This makes Z8 detection harder: no anomalous outbound network activity from VM-B, only the response to the caller who already has legitimate runCommand access. The exfiltration is a data-in-response pattern that only appears in Azure Compute diagnostic logs (off by default).

### D-Z8-03: Custom role definition takes ~30 seconds to become assignable

**Observation.** When `azurerm_role_definition` creates a custom role and the same Terraform apply immediately creates an `azurerm_role_assignment` referencing that role, the assignment sometimes fails with "role definition not found" or "role definition not yet propagated". This is different from role assignment propagation (D-Z7-03) — this is *role definition* propagation, which is a separate delay.

**Resolution.** Inserted `time_sleep.wait_for_role_definition` (30 seconds) between role definition creation and role assignment. Reliable across runs. In production Terraform patterns, this is captured by explicit `depends_on` plus a small delay.

**Documented for completeness.** Not a new attack finding — a Terraform reliability pattern specific to Azure custom roles.

## Attack Steps

1. Establish SSH access to VM-A as `azureuser`.
2. From VM-A, query IMDS for MI-A's ARM-scoped token.
3. `POST /subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/virtualMachines/{vm_b_name}/runCommand?api-version=2023-03-01` with `commandId=RunShellScript` and a bash script that queries local IMDS on VM-B, prints the resulting token to stdout with delimited markers.
4. Poll `Azure-AsyncOperation` URL every 10s until status is `Succeeded`.
5. Parse `properties.output.value[0].message` for the MI-B token between the delimiter markers.
6. Use MI-B token to PATCH tag on RG — succeeds via MI-B's subscription-Contributor scope.

## Running the PoC

```bash
# 0. Context
az account show --query name -o tsv     # personal MSA
export TF_VAR_subscription_id=$(az account show --query id -o tsv)
export TF_VAR_tenant_id=$(az account show --query tenantId -o tsv)

# 1. Deploy
cd environments/scenarios/Z8_vm_run_command_abuse
terraform init && terraform apply -auto-approve

# 2. Wait for role assignment propagation (~60s total from apply completion)
sleep 60

# 3. Ship exploit
terraform output -json > /tmp/z8_output.json
VM_A_IP=$(jq -r '.vm_a_public_ip.value' /tmp/z8_output.json)

SSH_OPTS=(-i ~/.ssh/id_rsa \
          -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
          -o PubkeyAcceptedAlgorithms=+ssh-rsa \
          -o HostKeyAlgorithms=+ssh-rsa)

scp "${SSH_OPTS[@]}" \
    ../../../attacks/Z8_vm_run_command_abuse/exploit.py \
    /tmp/z8_output.json \
    azureuser@$VM_A_IP:~/

# 4. Execute
ssh "${SSH_OPTS[@]}" azureuser@$VM_A_IP \
    'cloud-init status --wait 2>/dev/null; \
     python3 exploit.py --tf-output z8_output.json --log verification_log.txt'
```

## Captured Output (PoC Verification)

Full sanitized PoC log is committed as `verification_log.txt`. Raw log (containing actual subscription, tenant, MI principal IDs, VM public IP, VM-B name, and custom role name) is retained in `~/.pathtriage-private/`.

The exploit produces a final verification line of the form:

```
[+] Path Z8 verified: MI-A (VM Diagnostic Runner custom role, narrow) ->
                      POST runCommand -> arbitrary shell exec as root on VM-B ->
                      VM-B IMDS -> MI-B token (Contributor at subscription) ->
                      token exfiltrated via runCommand response ->
                      RG tag write succeeds via MI-B's Contributor scope
```

## Comparison to AWS Analogue

| Dimension | AWS P1 (PassRole + RunInstances) | Azure Z8 (VM Run Command Abuse) |
|---|---|---|
| Attacker's initial privilege | `iam:PassRole` + `ec2:RunInstances` on target role | Custom role with `runCommand/action` on target VM |
| Escalation mechanism | Launch new EC2 instance with elevated instance profile | Execute code on existing VM with elevated MI |
| Target state | New instance created with elevated role | Existing VM's MI token exfiltrated |
| Compute footprint | New VM billed, appears in inventory | No new resource, in-place execution |
| Detection at compute plane | `RunInstances` event with elevated `IamInstanceProfile` | `runCommand/action` event, no new resource |
| Persistence of escalation | Persistent until instance terminates | Ephemeral — token valid ~24h, no follow-up asset |
| Token/credentials exfiltration channel | Instance metadata service on new VM | runCommand response body |
| Preventive control | SCP: deny PassRole to admin roles + RunInstances scope | RBAC: custom role denylist for runCommand + Compute Policy |

**Structural finding**: AWS P1 creates a new elevated resource; Azure Z8 abuses an existing one. From a detection standpoint:
- AWS P1 creates a durable audit trail (a new VM exists post-attack).
- Azure Z8 leaves no persistent artifact beyond the `runCommand` event itself. Once the token is used and expires, the attack is "clean" — no infrastructure changes remain.

This makes Z8 attribution harder post-hoc. AWS defenders can find the malicious instance; Azure defenders must have captured the runCommand event and correlated with subsequent token use. Documented as a comparative finding for thesis Section 4.

**Additional structural finding**: Azure `runCommand` has no direct AWS equivalent for existing EC2 instances (`ssm:SendCommand` is analogous but requires SSM agent + IAM permissions on the SSM instance). This is one of the cleanest cross-cloud primitive matches — both clouds provide a "run code on an existing VM via control plane" primitive, and both have identical structural weaknesses when the calling identity has narrow-looking access to the primitive.

## Detection Preview (full rules in W8 defender-output module)

| Signal | Source | Primitive |
|---|---|---|
| `Microsoft.Compute/virtualMachines/runCommand/action` by an MI/SP whose baseline never calls runCommand | `AzureActivity` | Baseline-anomaly on caller |
| `runCommand` execution on a VM whose MI has substantially broader authority than the caller's own scope | Activity Log + role assignment inventory correlated | Privilege-delta anomaly (compute hijack primitive) |
| `runCommand` response body containing base64 patterns matching JWT structure (`eyJ...`) | Storage/diagnostic if enabled | Token exfiltration signal (post-facto only) |
| New AAD SignInLog for VM-B's MI from a caller IP not previously associated with VM-B's location | AAD SignInLogs | Token re-use from unexpected origin |

Note: the strongest detection is at the compute plane (runCommand event with anomalous caller/target scope combination). Post-facto detection via SignInLog anomaly is possible but requires knowing which MI is associated with which host — a correlation not always cleanly available.

## Cleanup

```bash
cd environments/scenarios/Z8_vm_run_command_abuse
terraform destroy -auto-approve
```

The tag `pathtriage-z8=owned` set by the exploit on `pathtriage-rg` is removed when the RG's tags default is next updated; it does not require explicit cleanup. To remove manually:

```bash
az tag update --resource-id /subscriptions/$(az account show --query id -o tsv)/resourceGroups/pathtriage-rg \
    --operation delete --tags pathtriage-z8=owned
```

## References

- MITRE ATT&CK [T1651 — Cloud Administration Command](https://attack.mitre.org/techniques/T1651/)
- MITRE ATT&CK [T1550.001 — Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- Microsoft Learn — [Run Command for Linux VMs](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/run-command)
- Microsoft Learn — [Custom roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)
- Microsoft Learn — [Managed identities for Azure resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- AWS docs — [ssm:SendCommand](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html) (Azure runCommand analogue)
