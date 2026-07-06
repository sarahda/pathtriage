# Primitive 04 — Per-Path Signature Details

## P7 — Lambda Env-Var Credential Theft

**Attack summary**: attacker with `lambda:GetFunctionConfiguration` reads a Lambda function's environment variables that legitimately (or accidentally) contain long-term IAM access keys. Attacker uses those keys from their own principal to perform elevated actions.

**Signature on this primitive**:

- Event 1 (read): `lambda:GetFunctionConfiguration` on a function whose `Environment.Variables` object contains fields.
- Event 2 (use, within 60 min): first-ever use of a new `userIdentity.accessKeyId` by a principal that shares source IP or user-agent with the reader.
- Correlation: matching source IP (attacker uses stolen creds from same egress) OR matching user-agent.
- Fire reason: `lambda_env_var_correlated_novel` (if first-time surface access) or `lambda_env_var_correlated` (if reader has prior surface access).
- Confidence: **high** (if novel + shared_ip + shared_ua), **high** (if novel + one of shared), **medium** (if not novel + both shared).

**Baseline join contribution**: essential. Without the access-key-ID novelty check, the primitive would fire on every Lambda config read (millions per day). Novelty restricts fires to genuine credential-leak events.

**MTTD expectation**: 1-60 minutes. Fire occurs on the use event (event 2), which requires the correlation window to elapse. Attackers using stolen keys immediately produce sub-minute MTTD; delayed use pushes MTTD toward the correlation window bound.

**Comparison-tool coverage**:

- **Cloudsplaining**: **miss** — analyses IAM policies, not Lambda env vars.
- **Prowler**: **partial** — check `lambda_function_no_secrets_in_variables` (v4.1+) scans Lambda functions and flags env vars that look like access keys. Detects the misconfiguration, not the exploitation.
- **Datadog CloudSIEM**: **miss** — no rule for this pattern. Datadog has "Lambda function environment variables scan" but it is a compliance report, not a real-time detection.
- **Sigma HQ cloud**: **miss** — no rule.
- **CIS AWS Foundations v3.0**: **miss** — no relevant control.

## P8 — S3 Credential Harvest

**Attack summary**: attacker with `s3:GetObject` reads bucket objects containing embedded IAM access keys — `terraform.tfstate` (which stores plaintext credentials by default in older Terraform versions or when providers are misused), `.env` config files, or `credentials` files uploaded to S3 as backup. Attacker uses those keys.

**Signature on this primitive**:

- Event 1 (read): `s3:GetObject` on a key matching the primitive's file-pattern list (`.tfstate`, `.env`, `credentials*`, `.aws/*`, `config.json`, `secrets*`).
- Event 2 (use, within 60 min): first-ever use of a new `userIdentity.accessKeyId`, correlated by IP or UA to the reader.
- Fire reason: `s3_object_correlated_novel` or `s3_object_correlated`.
- Confidence: same as P7.

**Baseline join contribution**: same as P7 — access-key novelty is the critical filter. Additionally, the first-time-surface-access flag helps distinguish attack from legitimate operations (Terraform reading its own state file has a long access history; attackers reading tfstate files have a first-time signature).

**MTTD expectation**: same as P7 (1-60 min, use-event bound).

**Comparison-tool coverage**:

- **Cloudsplaining**: **miss** — policy-level analysis, not object-level.
- **Prowler**: **partial** — `s3_bucket_object_public_access` and similar rules flag buckets with public exposure of sensitive-named objects. Does not catch legitimate-permission read of credential files.
- **Datadog CloudSIEM**: **partial** — has a rule `Suspicious S3 access from unexpected source` but it does not filter for credential-file patterns nor correlate with subsequent access-key use.
- **Sigma HQ cloud**: **partial** — has `aws_susp_saml_activity` and related rules for credential-related actions, but no rule matches the GetObject + tfstate pattern directly.
- **CIS AWS Foundations v3.0**: **partial** — Control 2.1 requires S3 bucket encryption. Encryption does not prevent authorised readers from extracting credentials.

## Coverage Matrix Row

For inclusion in `methodology/related_work.md` §3:

| Path | Cloudsplaining | Prowler | Datadog | Sigma | CIS | PathTriage primitive |
|---|---|---|---|---|---|---|
| P7 | miss | partial | miss | miss | miss | **04** |
| P8 | miss | partial | partial | partial | partial | **04** |

Structural gap: **P7 is missed by 4 of 5 comparison tools**. Only Prowler has any coverage, and it's a compliance scan, not runtime detection. **This is a strong contribution point** — primitive 04 is the only runtime detection for the Lambda env-var theft pattern in the surveyed tools.

P8 has broader partial coverage but no tool ties the object read to subsequent access-key use. The **correlation** is primitive 04's contribution.

## Cross-primitive context — credential vs identity primitives

Primitive 04 detects credentials that are stored in one place and used from another (theft primitive). This is distinct from primitives 01-03, which detect abuse of credentials/identities already established. The two categories serve different defender needs:

- Primitives 01-03: catch abuse in progress (attacker already has stolen credentials, or has direct elevated authority).
- Primitive 04: catches the theft event itself, potentially before broader abuse.

Primitive 04's coverage of P7/P8 also has a **structural precondition**: the legitimate keys must have been stored in a discoverable surface in the first place. If the organisation uses only role-based access (no long-term keys), P7/P8 become impossible and primitive 04 has no fires. This is the ideal end state; primitive 04 is the detection during the transition.
