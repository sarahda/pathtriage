# PathTriage

**Exploitability-Ranked IAM Attack-Path Discovery and Defender-Output Synthesis for AWS and Azure**

A Python tool that discovers IAM privilege escalation paths in AWS and Azure cloud environments, ranks them by exploitability using a defended metric, and generates defender output — detection queries and remediation policies — for each ranked path.

## Project Context

Master's research project conducted within the UNSW COMP9301 (Term 2 2026) and COMP9302 (Term 3 2026) framework.

## Status

🚧 **Work in progress — COMP9301 Week 3 (Term 2 2026)**

- Verified attack paths: **6 / 8** target (ahead of W4 milestone)
- Tool skeleton: `pathtriage scan --provider aws` enumerates IAM and builds the initial attack graph

## Attack Path Catalogue

| #  | Path | Provider | Mechanism | Status |
|----|------|----------|-----------|--------|
| 01 | [PassRole + RunInstances](attacks/01_passrole/)                   | AWS | EC2 role-assumption via instance profile                 | ✅ Verified |
| 02 | [IMDS SSRF Credential Theft](attacks/02_imds_ssrf/)               | AWS | SSRF → IMDSv1 → role credential extraction              | ✅ Verified |
| 03 | [CreatePolicyVersion Escalation](attacks/03_createpolicyversion/) | AWS | Self-attached customer-managed policy rewrite            | ✅ Verified |
| 04 | [AssumeRole Chain](attacks/04_assume_role_chain/)                 | AWS | Transitive trust topology: user → R1 → R2 (admin)        | ✅ Verified |
| 05 | [AttachPolicy Escalation](attacks/05_attachpolicy/)               | AWS | Self-attach `AdministratorAccess` via `iam:AttachUserPolicy` | ✅ Verified |
| 06 | [EC2 Instance Profile Abuse](attacks/06_instance_profile/)        | AWS | IMDS extraction from EC2 with admin role, used off-box   | ✅ Verified |
| 07–08 | *in progress*                                                  | AWS | Lambda env-var theft · S3 credential harvest             | 🕒 Planned (W6–W7) |

Each path includes a Terraform-deployed vulnerable lab, an end-to-end `exploit.py`, and a verification log. Defender output (detection queries + remediation policies) and exploitability scoring are designed cross-path in later weeks (W5 / W7) to capture **convergence** rather than duplicating per-path — e.g. a single IMDS-extraction detection covers Paths 1, 2, and 6.

## Repository Structure

- `attacks/` — Per-path catalogue (PoC scripts, READMEs, MITRE mappings, verification logs)
- `pathtriage/` — Core Python package
  - `cli/` — `pathtriage` command entry point
  - `enumerators/` — Provider-specific IAM enumeration (AWS via `boto3`; Azure planned)
  - `graph/` — NetworkX-based attack graph construction
- `environments/` — Terraform lab configurations
  - `baseline/` — Shared VPC, subnet, and low-privileged user
  - `scenarios/NN_<path>/` — Per-path vulnerable environment
- `docs/` — Architecture, evaluation protocol, reports

## License

MIT — see [LICENSE](LICENSE)

## Responsible Use

This project includes proof-of-concept code for IAM attack paths intended for security research and defensive purposes. PoCs should only be run in isolated, intentionally vulnerable environments (e.g., CloudGoat scenarios, or the Terraform labs in `environments/`). Do not run against production systems without explicit authorisation.