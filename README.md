## Status

🚧 **Work in progress — COMP9301 Week 3 (Term 2 2026)**

- Verified attack paths: **8 / 8** target ✅ (D1 HD verification milestone reached)
- Tool skeleton: `pathtriage scan --provider aws` enumerates IAM and builds the initial attack graph

## Attack Path Catalogue

| #  | Path | Provider | Mechanism | Status |
|----|------|----------|-----------|--------|
| 01 | [PassRole + RunInstances](attacks/01_passrole/)                       | AWS | EC2 role-assumption via instance profile               | ✅ Verified |
| 02 | [IMDS SSRF Credential Theft](attacks/02_imds_ssrf/)                   | AWS | SSRF → IMDSv1 → role credential extraction             | ✅ Verified |
| 03 | [CreatePolicyVersion Escalation](attacks/03_createpolicyversion/)     | AWS | Self-attached customer-managed policy rewrite          | ✅ Verified |
| 04 | [AssumeRole Chain](attacks/04_assume_role_chain/)                     | AWS | Transitive trust topology: user → R1 → R2 (admin)      | ✅ Verified |
| 05 | [AttachPolicy Escalation](attacks/05_attachpolicy/)                   | AWS | Self-attach `AdministratorAccess` via `iam:AttachUserPolicy` | ✅ Verified |
| 06 | [EC2 Instance Profile Abuse](attacks/06_instance_profile/)            | AWS | IMDS extraction from EC2 with admin role, used off-box | ✅ Verified |
| 07 | [Lambda Env-Var Credential Theft](attacks/07_lambda_env_theft/)       | AWS | Long-term IAM keys leaked via Lambda env vars          | ✅ Verified |
| 08 | [S3 Credential Harvest](attacks/08_s3_credential_harvest/)            | AWS | Long-term IAM keys leaked via bucket objects (.tfstate, .env) | ✅ Verified |

The catalogue spans **four convergence points** in defender-output design:

| Convergence point | Paths | Defender primitive |
|---|---|---|
| IMDS credential extraction | 1, 2, 6 | IMDS read + off-box credential use detection |
| IAM policy modification    | 3, 5    | CloudTrail IAM event monitoring |
| Trust topology exploit     | 4       | Chained `sts:AssumeRole` pattern detection |
| Credential discovery       | 7, 8    | Surface-API read + off-band AKIA use correlation |

Eight paths × four detection primitives — the catalogue is structured around these convergence points (N2), not duplicated per-path. Defender output and exploitability scoring are designed cross-path in W5 / W7.