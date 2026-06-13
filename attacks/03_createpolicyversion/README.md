# Path 03 — CreatePolicyVersion Privilege Escalation

## Overview

A low-privileged user who holds `iam:CreatePolicyVersion` (and
`iam:SetDefaultPolicyVersion`) on a **customer-managed policy attached to
themselves** can rewrite the very policy that defines their own permissions.
They create a new policy version granting `Action:* Resource:*`, set it as the
default, and become effectively administrator. No EC2 instance, no role
assumption — escalation happens entirely at the IAM policy layer.

This is the most distinct path in the catalogue so far: Paths 1 and 2 are
EC2/IMDS-based, this one is *pure IAM*. That contrast is the catalogue-diversity
evidence for the Midway Report.

## Attack Flow

```
  low-priv user (iam:CreatePolicyVersion on policy P, attached to self)
        |
        |  baseline probe: iam:CreateUser  -> AccessDenied
        v
  CreatePolicyVersion(P, doc = {Action:*, Resource:*}, SetAsDefault=true)
        |
        v
  P's default version now grants *:*  ==> user's effective perms = admin
        |
        |  re-probe: iam:CreateUser  -> Success
        v
  privilege escalation confirmed
```

## MITRE ATT&CK

- **T1098.003** — Account Manipulation: Additional Cloud Roles / permission
  modification (effective-permission change via managed-policy rewrite)

## Design note — self-attach vs role variant

The W2 scope line read "policy attached to a high-priv role … validated from a
role-assuming session." I built the **self-attached** variant instead because:

1. It is the canonical Rhino Labs `CreatePolicyVersion` primitive and the
   cleanest to verify (one user, one before/after probe, no assume-role hop).
2. It maximises catalogue diversity — a true *user-level, pure-IAM* path that
   contrasts sharply with Path 1's role/EC2 mechanics. A role-assumption variant
   would partially overlap Path 1's "land on a role" shape.

If you'd rather demonstrate the role variant (user has CreatePolicyVersion on a
policy attached to a role they can assume; rewrite then assume), say the word and
I'll add it as Path 3b — it's a small Terraform/PoC delta.

## Prerequisites

- Baseline deployed (low-priv user exported as `low_priv_user_name`).
- Low-priv credentials exported in the environment for the PoC.

## Lab Deployment

```bash
cd environments/scenarios/03_createpolicyversion
terraform init
terraform apply        # yes
terraform output scenario_summary
terraform output -raw escalation_policy_arn
```

## Attack Steps

```bash
# export the low-priv credentials (named profile or env vars), then:
python3 attacks/03_createpolicyversion/exploit.py \
  --policy-arn "$(cd environments/scenarios/03_createpolicyversion && terraform output -raw escalation_policy_arn)"
```

The PoC: confirms identity → baseline probe (`iam:CreateUser` denied) → creates
and defaults a `*:*` version → waits for propagation → re-probes (now succeeds).

## Expected Output

Captured in `verification_log.txt`. Shows `iam:CreateUser` denied before, the new
default version id, then `iam:CreateUser` succeeding after — escalation confirmed.

## Vulnerable Configuration

```hcl
# Dangerous statement on the policy, scoped to its own ARN:
{
  Effect   = "Allow"
  Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
  Resource = "<this policy's own ARN>"
}
# ...and the policy is attached to the low-priv user.
```

## Why This Works

Effective permissions are evaluated against a managed policy's **default
version**. `SetDefaultPolicyVersion` lets the holder choose which version is
default, and `CreatePolicyVersion` lets them author its contents. Holding both on
a policy attached to yourself is a closed loop: you author your own permissions.
The grant looks narrow in an audit (two `iam:` actions on a single resource), but
the resource *is* the permission boundary.

## Defender Output *(deferred — W7)*

- Detection: CloudTrail `CreatePolicyVersion` / `SetDefaultPolicyVersion` where
  the new document widens scope (esp. `Action:*`), correlated to the principal
  that owns/attaches the policy.
- Mitigation: SCP denying `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`
  outside a break-glass role; permission-boundary on the user.

## Exploitability Score *(deferred — W5)*

Scored under the unified rubric once ≥5 paths exist. Note this path needs **no**
network position and **no** second hop, so it should rank high on ease.

## Status

- [x] Terraform vulnerable environment
- [x] PoC script (`exploit.py`)
- [x] Verification log (`verification_log.txt`)
- [ ] Defender output (deferred to W7)
- [ ] Exploitability score (deferred to W5)

## Cleanup

```bash
cd environments/scenarios/03_createpolicyversion && terraform destroy
# If the PoC left extra policy versions, terraform destroy still removes the
# whole policy; no manual version cleanup needed.
```

## References

- Rhino Security Labs, AWS IAM privilege escalation methods (CreatePolicyVersion)
- AWS IAM docs, "Versioning IAM policies"
