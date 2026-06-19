# Path 08 — S3 Credential Harvest

## Overview

A low-privileged user with broad S3 read permissions enumerates buckets,
identifies credential-bearing objects by extension and name heuristics,
downloads them, and parses the contents for AWS credentials. The harvested
keys are used **off-band** via a separate boto3 Session to confirm
escalation.

This is **credential discovery in the storage surface** — the
storage-surface counterpart to Path 07 (Lambda environment-variable theft).
Like Path 07, the misconfiguration is invisible to IAM-permission-graph
analysis tools: it lives in bucket *content*, not in IAM policy.

## Attack flow

```
low-priv user (s3:ListAllMyBuckets, s3:ListBucket, s3:GetObject)
    ↓ ListBuckets                  → enumerate buckets
    ↓ ListObjects on each          → filter by name/extension heuristics
    ↓ GetObject on candidates      → download likely credential files
    ↓ parse format-specific        → .tfstate, .env, generic AKIA regex
attacker harvests AccessKeyId + SecretAccessKey
    ↓ used off-band via boto3 Session
attacker is now the embedded identity (AdministratorAccess) — anywhere
```

## MITRE ATT&CK for Cloud

- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1530** — Data from Cloud Storage Object
- **T1078.004** — Valid Accounts: Cloud Accounts (the off-band identity use)

## Prerequisites

- Baseline lab deployed
- Scenario 08 lab deployed: `cd environments/scenarios/08_s3_credential_harvest && terraform apply`
- Python 3 with `boto3` available
- Low-priv access key + secret exported as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`

## Attack steps

```bash
# 1. Switch to low-priv credentials
cd environments/baseline
export AWS_ACCESS_KEY_ID=$(terraform output -raw low_priv_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(terraform output -raw low_priv_secret_access_key)
unset AWS_SESSION_TOKEN AWS_PROFILE

# 2. Run the exploit
python attacks/08_s3_credential_harvest/exploit.py
```

## Expected output

```
[*] acting as: arn:aws:iam::<acct>:user/pathtriage-low-priv-attacker
[*] Step 1: baseline probe — low-priv user iam:CreateUser?
    [+] iam:CreateUser denied (as expected)
[*] Step 2: enumerating S3 buckets
    [+] found N bucket(s)
[*] Step 3: listing objects, filtering by credential-shape heuristics
    [+] 2 candidate object(s):
        - s3://pathtriage-08-infra-state-<hex>/app/configs/deployment.env
        - s3://pathtriage-08-infra-state-<hex>/infra/prod/terraform.tfstate
[*] Step 4: downloading candidates and parsing for AWS credentials
    [+] s3://.../deployment.env: credentials extracted

[*] Step 5: using harvested credentials off-band via boto3
        AccessKeyId:     AKIA...
        SecretAccessKey: xxxx...xxxx (masked)
        Source:          s3://.../deployment.env
        Type:            long-term IAM key
    [+] now: arn:aws:iam::<acct>:user/pathtriage-08-deploy-user
[*] Step 6: privileged probe — iam:CreateUser as the stolen identity
    [+] iam:CreateUser SUCCEEDS — stolen identity is admin

[+] Path 08 verified: s3:GetObject -> file parse -> off-band admin
```

See `verification_log.txt` for a captured run.

## Vulnerable configuration

The lab demonstrates two file formats in the same bucket to model real
multi-format scenarios:

**A. Terraform state file with credentials in cleartext** — the canonical
"state in S3" failure pattern:

```json
{
  "resources": [
    {
      "type": "aws_iam_access_key",
      "name": "deploy_key",
      "instances": [
        {
          "attributes": {
            "id":     "AKIA...",
            "secret": "<40-char secret>",
            "user":   "pathtriage-08-deploy-user"
          }
        }
      ]
    }
  ]
}
```

**B. Deployment .env file** — the classic `KEY=VALUE` leak:

```
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=<40-char secret>
```

Both objects are in a private bucket with public access fully blocked.
**The breach is internal pivoting, not public exposure.** The low-priv
user is a legitimate principal in the account with overly broad S3 read
permissions:

```hcl
{
  Effect = "Allow"
  Action = [
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:GetObject",
  ]
  Resource = "*"
}
```

These permissions are routinely granted for monitoring, analytics, or
"audit" purposes. They appear unremarkable in an IAM permission graph.

## Why this works

The misconfiguration **does not appear in the IAM permission graph at
all**. The low-priv user holds standard read permissions; the embedded
credentials are in bucket content, which IAM-graph tools (PMapper,
BloodHound OpenGraph) do not inspect.

Terraform state files are particularly important to model. State files
contain `aws_iam_access_key` resources with raw `secret` attributes in
cleartext — by design, because Terraform must store the values it
provisions. Developers routinely store state in S3 for team
collaboration. When the state bucket's read permissions are too broad,
every secret Terraform has ever provisioned is leaked.

### Convergence with Path 7

Paths 7 and 8 form the catalogue's **credential-discovery convergence
point**:

| Path | Storage surface | Read permission |
|------|------------------|------------------|
| 07 — Lambda env-var theft  | Lambda function configuration | `lambda:GetFunctionConfiguration` |
| 08 — S3 credential harvest | S3 object content              | `s3:GetObject` |

Both bypass IAM-permission-graph analysis entirely. A single defender
output design — *API call to a credential-bearing surface, correlated
with subsequent off-band use of an AKIA-prefixed key from a new source
IP* — covers both. This is the empirical foundation for the **N2
convergence-based defender output** argument in the Midway Report.

### Severity

Like Path 7, the harvested credentials are **long-term IAM keys**
(AKIA-prefixed). They remain valid until rotated — often indefinitely.
This is strictly worse than the IMDS temp credentials in Path 6
(ASIA-prefixed, ~1 hour TTL). The exploitability rubric should reflect
this asymmetry.

## Deferred sections

- **Exploitability score** — applied W5 under the rubric in
  `docs/scoring_rubric.md`. Expected to score similarly to Path 7
  (long-term keys, high impact; broad S3 read is a common grant pattern).
- **Defender output** — generated W7 alongside Path 7. Will include:
  - CloudTrail query template for `GetObject` calls on objects whose
    keys match credential-shape patterns (`.env`, `.tfstate`,
    `credentials*`), correlated with subsequent use of any
    AKIA-prefixed key from a new source IP
  - SCP snippet denying `s3:GetObject` on objects matching credential
    patterns outside an allow-list of CI/CD roles
  - Bucket policy template denying `s3:GetObject` on `*.tfstate` for
    any principal other than the Terraform CI role

## Cleanup

```bash
cd environments/scenarios/08_s3_credential_harvest
terraform destroy -auto-approve

# Verify no orphans
aws s3api list-buckets \
    --query 'Buckets[?starts_with(Name, `pathtriage-08`)].Name' \
    --output text                  # should be empty

aws iam list-users \
    --query 'Users[?starts_with(UserName, `pathtriage-08`)].UserName' \
    --output text                  # should be empty

aws iam list-user-policies --user-name pathtriage-low-priv-attacker \
    --query 'PolicyNames'          # should NOT include pathtriage-08-can-read-s3
```

The bucket has `force_destroy = true` so `terraform destroy` removes the
objects before the bucket itself. The IAM user deletion automatically
invalidates the harvested long-term access key.

## References

- Rhino Security Labs — [AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) (credential discovery patterns)
- MITRE ATT&CK for Cloud — [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1530](https://attack.mitre.org/techniques/T1530/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- HashiCorp — [Sensitive data in Terraform state](https://developer.hashicorp.com/terraform/language/state/sensitive-data) (the canonical "state files leak" warning)
- AWS docs — [S3 bucket policy best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html)