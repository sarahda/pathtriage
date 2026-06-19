# Path 07 — Lambda Environment-Variable Credential Theft

## Overview

Lambda functions commonly hold AWS credentials, database connection strings,
or API tokens as plaintext environment variables. A user with
`lambda:GetFunctionConfiguration` on such functions can read those env vars
directly without invoking the function. This is **credential discovery** —
no IAM modification, no compute launch, no role assumption, no trust change.

The path matters because the extracted credentials are **long-term IAM keys**
(AKIA-prefixed, valid until rotated), strictly worse than the STS temp
credentials extracted in Path 06 (ASIA-prefixed, ~1 hour TTL).

## Attack flow

```
low-priv user (lambda:ListFunctions, GetFunctionConfiguration)
    ↓ ListFunctions
attacker enumerates available Lambda functions
    ↓ GetFunctionConfiguration on each
    ↓ pattern-match credential-shaped env var keys
attacker harvests AccessKeyId + SecretAccessKey from env vars
    ↓ used off-band via boto3 Session
attacker is now the embedded identity (AdministratorAccess) — anywhere
```

## MITRE ATT&CK for Cloud

- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1078.004** — Valid Accounts: Cloud Accounts (the off-band identity use)

## Prerequisites

- Baseline lab deployed
- Scenario 07 lab deployed: `cd environments/scenarios/07_lambda_env_theft && terraform apply`
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
python attacks/07_lambda_env_theft/exploit.py
```

## Expected output

```
[*] acting as: arn:aws:iam::<acct>:user/pathtriage-low-priv-attacker
[*] Step 1: baseline probe — low-priv user iam:CreateUser?
    [+] iam:CreateUser denied (as expected)
[*] Step 2: enumerating Lambda functions in region
    [+] found N function(s)
[*] Step 3: scanning each function's environment variables for credential patterns
    [+] pathtriage-07-internal-data-sync: credentials found in env vars
        env keys: ['BACKUP_AWS_ACCESS_KEY_ID', 'BACKUP_AWS_SECRET_ACCESS_KEY', ...]

[*] Step 4: using stolen credentials off-band via boto3
        AccessKeyId:     AKIA...
        SecretAccessKey: xxxx...xxxx (masked)
        Source:          Lambda function pathtriage-07-internal-data-sync (env vars)
        Type:            long-term IAM key
    [+] now: arn:aws:iam::<acct>:user/pathtriage-07-backup-user
[*] Step 5: privileged probe — iam:CreateUser as the stolen identity
    [+] iam:CreateUser SUCCEEDS — stolen identity is admin

[+] Path 07 verified: lambda:GetFunctionConfiguration -> env-var read -> off-band admin
```

See `verification_log.txt` for a captured run.

## Vulnerable configuration

Two layers of misconfiguration combine:

**Layer 1 — long-term IAM keys exist at all.**

```hcl
resource "aws_iam_user" "leaked_identity" {
  name = "pathtriage-07-backup-user"
}

resource "aws_iam_access_key" "leaked_identity" {
  user = aws_iam_user.leaked_identity.name
}
```

In a hardened design this user would not exist; the Lambda would use its
own execution role for any AWS API access, with cross-account work mediated
by role assumption rather than long-term keys.

**Layer 2 — keys stored in plaintext env vars.**

```hcl
resource "aws_lambda_function" "with_secrets" {
  environment {
    variables = {
      BACKUP_AWS_ACCESS_KEY_ID     = aws_iam_access_key.leaked_identity.id
      BACKUP_AWS_SECRET_ACCESS_KEY = aws_iam_access_key.leaked_identity.secret
    }
  }
}
```

In a hardened design these would live in AWS Secrets Manager or Parameter
Store with KMS encryption, retrieved at runtime by the function's execution
role with `secretsmanager:GetSecretValue` constrained to the specific secret.

> **Note on reserved env var names.** AWS Lambda rejects `AWS_ACCESS_KEY_ID`
> and `AWS_SECRET_ACCESS_KEY` as reserved keys. The lab uses `BACKUP_AWS_*`
> prefixed names — which is more realistic in any case, matching the common
> real-world pattern of prefixing service-account keys.

## Why this works

The path's distinctive characteristic is its **invisibility to IAM-layer
analysis tools**. PMapper, BloodHound OpenGraph, and AzureHound all
operate at the IAM permission graph layer: who can do what on which
resource. The misconfiguration here is not in the IAM permission graph
at all — it is in the *content* of a Lambda function's environment
variables. The low-priv user holds legitimate-looking read permissions
(`lambda:GetFunctionConfiguration`) which exist in countless AWS accounts
for monitoring and audit purposes; the vulnerability emerges only when
those read permissions are combined with poor secret-storage hygiene in
function configuration.

This makes Path 07 important for the catalogue specifically because it
*surfaces a class of finding existing IAM-layer tools cannot enumerate*.

### Convergence with Path 8

Paths 7 and 8 form a credential-discovery convergence point:

| Path | Storage surface | Read permission required |
|------|------------------|---------------------------|
| 07 — Lambda env-var theft  | Lambda function configuration | `lambda:GetFunctionConfiguration` |
| 08 — S3 credential harvest | S3 object content             | `s3:GetObject` |

Both bypass IAM-permission-graph analysis entirely. Defender output for
both must be log-based on API usage patterns rather than IAM events.

### Severity relative to Path 6

Paths 6 and 7 both end in "credential extraction → off-band use." But:

| Property | Path 06 (IMDS) | Path 07 (Lambda env vars) |
|----------|------------------|------------------------------|
| Credential type   | STS temp (ASIA-prefix) | Long-term IAM (AKIA-prefix) |
| TTL               | ~1 hour                 | Until rotated (often never) |
| Detectability post-theft | Token expiry naturally limits exposure | Stolen key works indefinitely |

Path 07 is strictly worse on every dimension. The exploitability rubric
should reflect this.

## Deferred sections

- **Exploitability score** — applied W5 under the rubric in
  `docs/scoring_rubric.md`. Expected to score high on impact (long-term
  keys, no expiry) and moderate on prerequisite (`lambda:Get*` permissions
  are routinely granted for monitoring).
- **Defender output** — generated W7. Will include:
  - CloudTrail query template for `GetFunctionConfiguration` API calls
    where the principal does not match the function's invocation history,
    correlated with subsequent use of any AKIA-prefixed key from a new
    source IP
  - SCP snippet denying `lambda:GetFunctionConfiguration` outside an
    allow-list of audit/observability roles, and requiring environment
    variables containing credential-shaped keys to be stored in Secrets
    Manager via a CI-time linter (out-of-band of SCP itself)

## Cleanup

```bash
cd environments/scenarios/07_lambda_env_theft
terraform destroy -auto-approve

# Verify no orphans remain
aws lambda list-functions \
    --query 'Functions[?starts_with(FunctionName, `pathtriage-07`)].FunctionName' \
    --output text                  # should be empty

aws iam list-users \
    --query 'Users[?starts_with(UserName, `pathtriage-07`)].UserName' \
    --output text                  # should be empty

aws iam list-roles \
    --query 'Roles[?starts_with(RoleName, `pathtriage-07`)].RoleName' \
    --output text                  # should be empty

aws iam list-user-policies --user-name pathtriage-low-priv-attacker \
    --query 'PolicyNames'          # should NOT include pathtriage-07-can-read-lambda
```

The IAM user being deleted automatically invalidates the long-term access
key extracted during the exploit; this is the lab's "credential invalidation"
mechanism and is reliable. There is no out-of-band cleanup as in Path 05.

## References

- Rhino Security Labs — [Lambda Privilege Escalation methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- MITRE ATT&CK for Cloud — [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- AWS docs — [Lambda environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html) (note reserved key restrictions)
- AWS docs — [Best practices: secrets in Lambda](https://docs.aws.amazon.com/secretsmanager/latest/userguide/lambda-functions.html)