# PathTriage

> Exploitability-ranked IAM attack-path discovery and defender-output synthesis for AWS and Azure.

## Status

**🚧 Work in progress — COMP9301 Week 5 (Term 2 2026), post-midway**

- **Midway report submitted** — verified catalogue, rubric v1, prototype design (June 2026)
- **AWS arm complete** — 8 / 8 paths verified end-to-end ✅
- **Azure arm in progress** — 1 / 8 paths verified (Z1); Z2–Z8 in pipeline
- **Tool skeleton**: `pathtriage scan --provider aws` enumerates IAM and builds the initial attack graph (Azure enumerator scheduled for W7–8)
- **Defender-output module**: AWS detection rules + SCP mitigations in progress (W6–7); Azure equivalents in W8

## Attack Path Catalogue

### AWS (8 / 8 verified)

| # | Path | Mechanism | Status |
|---|---|---|---|
| 01 | PassRole + RunInstances | EC2 role-assumption via instance profile | ✅ Verified |
| 02 | IMDS SSRF Credential Theft | SSRF → IMDSv1 → role credential extraction | ✅ Verified |
| 03 | CreatePolicyVersion Escalation | Self-attached customer-managed policy rewrite | ✅ Verified |
| 04 | AssumeRole Chain | Transitive trust topology: user → R1 → R2 (admin) | ✅ Verified |
| 05 | AttachPolicy Escalation | Self-attach `AdministratorAccess` via `iam:AttachUserPolicy` | ✅ Verified |
| 06 | EC2 Instance Profile Abuse | IMDS extraction from EC2 with admin role, used off-box | ✅ Verified |
| 07 | Lambda Env-Var Credential Theft | Long-term IAM keys leaked via Lambda env vars | ✅ Verified |
| 08 | S3 Credential Harvest | Long-term IAM keys leaked via bucket objects (`.tfstate`, `.env`) | ✅ Verified |

### Azure (1 / 8 verified)

| # | Path | Mechanism | Status |
|---|---|---|---|
| Z1 | VM Managed Identity via IMDS | System-Assigned MI granted Contributor at subscription scope; IMDS token used off-box | ✅ Verified |
| Z2 | Service Principal Credential Theft | SP `clientSecret` exposed in config / pipeline | 🚧 W6 |
| Z3 | Role Assignment Manipulation | `Microsoft.Authorization/roleAssignments/write` → self-Owner | 🚧 W6 |
| Z4 | Custom Role Definition Abuse | `roleDefinitions/write` → inject `Actions` | 🚧 W7 |
| Z5 | Key Vault Secret Escalation | Key Vault RBAC / access policy → read secrets → reuse | 🚧 W7 |
| Z6 | Storage Account Key Abuse | `listKeys` → `.tfstate` / connection strings | 🚧 W8 |
| Z7 | Managed Identity / SP Chain | MI/SP assigns role to / impersonates 2nd identity | 🚧 W8 |
| Z8 | VM Run Command Abuse | `virtualMachines/runCommand/action` → exec as MI | 🚧 W8 |

## Convergence Points

The catalogue is structured around defender-relevant convergence points rather than per-path detection. Eight AWS paths collapse to four detection primitives; Azure paths are expected to converge onto a similar primitive set.

| Convergence point | AWS paths | Azure paths (expected) | Defender primitive |
|---|---|---|---|
| IMDS credential extraction | 1, 2, 6 | Z1, Z6, Z8 | IMDS read + off-box credential use detection |
| IAM policy modification | 3, 5 | Z3, Z4 | CloudTrail / Activity Log policy-mutation monitoring |
| Trust topology exploit | 4 | Z7 | Chained `sts:AssumeRole` / cross-identity assignment detection |
| Credential discovery | 7, 8 | Z2, Z5, Z6 | Surface-API read + off-band long-term key reuse correlation |

Eight AWS paths × four detection primitives = **2:1 average convergence ratio**. Defender output and exploitability scoring are designed cross-path in W6 / W7, not duplicated per-path.

