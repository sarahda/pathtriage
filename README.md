# PathTriage

Exploitability-ranked IAM attack-path discovery and defender-output synthesis for AWS and Azure.

## Status

🚧 **Work in progress** — COMP9301 Week 5 (Term 2 2026), post-midway

- **Midway report submitted** — verified catalogue, rubric v1, prototype design (June 2026)
- **AWS arm complete** — 8 / 8 paths verified end-to-end ✅
- **Azure arm in progress** — **4 / 8 paths verified** (Z1–Z4); Z5–Z8 in pipeline
- **Tool skeleton**: `pathtriage scan --provider aws` enumerates IAM and builds the initial attack graph (Azure enumerator scheduled for W7–8)
- **Defender-output module**: 14-hour build planned; methodology skeleton committed (`attacks/_defender_output/`); primitive build begins W6

## Attack Path Catalogue

### AWS (8 / 8 verified)

| # | Path | Mechanism | Status |
|---|------|-----------|--------|
| 01 | PassRole + RunInstances | EC2 role-assumption via instance profile | ✅ Verified |
| 02 | IMDS SSRF Credential Theft | SSRF → IMDSv1 → role credential extraction | ✅ Verified |
| 03 | CreatePolicyVersion Escalation | Self-attached customer-managed policy rewrite | ✅ Verified |
| 04 | AssumeRole Chain | Transitive trust topology: user → R1 → R2 (admin) | ✅ Verified |
| 05 | AttachPolicy Escalation | Self-attach `AdministratorAccess` via `iam:AttachUserPolicy` | ✅ Verified |
| 06 | EC2 Instance Profile Abuse | IMDS extraction from EC2 with admin role, used off-box | ✅ Verified |
| 07 | Lambda Env-Var Credential Theft | Long-term IAM keys leaked via Lambda env vars | ✅ Verified |
| 08 | S3 Credential Harvest | Long-term IAM keys leaked via bucket objects (`.tfstate`, `.env`) | ✅ Verified |

### Azure (4 / 8 verified)

| # | Path | Mechanism | Status |
|---|------|-----------|--------|
| Z1 | VM Managed Identity via IMDS | System-Assigned MI granted Contributor at subscription scope; IMDS token used off-box | ✅ Verified |
| Z2 | Service Principal Credential Theft | SP `clientSecret` leaked in App Service `app_settings`; MI reads via `Website Contributor` → OAuth2 `client_credentials` → subscription Contributor | ✅ Verified |
| Z3 | Role Assignment Manipulation | `Microsoft.Authorization/roleAssignments/write` (via UAA) → self-grant Owner on RG | ✅ Verified |
| Z4 | Custom Role Definition Abuse | `Microsoft.Authorization/roleDefinitions/write` (via Owner) → inject wildcard `*` into custom role `actions[]`, retroactive elevation of all assignees | ✅ Verified |
| Z5 | Key Vault Secret Escalation | Key Vault RBAC / access policy → read secrets → reuse | 🚧 W6 |
| Z6 | Storage Account Key Abuse | `listKeys` → `.tfstate` / connection strings | 🚧 W6 |
| Z7 | Managed Identity / SP Chain | MI/SP assigns role to / impersonates 2nd identity | 🚧 W7 |
| Z8 | VM Run Command Abuse | `virtualMachines/runCommand/action` → exec as MI | 🚧 W7 |

Azure paths Z2–Z8 are deployed on a separate personal-MSA subscription; Z1 remains on the UNSW Azure for Students subscription. Rationale documented in `attacks/Z2_sp_credential_theft/README.md` (D-Z2-01) — the UNSW tenant policy disables application registration, blocking any Azure path that requires Service Principal creation.

## Key Findings

Documented per-path in the individual READMEs; the ones with material contribution to thesis Section 4 (AWS↔Azure comparative analysis) are summarised here.

- **D-Z4-02 (undocumented Azure RBAC privilege-escalation guard)**. Azure silently reverts role-definition mutations whose new `actions[]` contain actions the calling principal does not already hold. A `PUT` returns 200 OK with the echoed body, but a backend validator reverts the persisted state within seconds. `User Access Administrator` cannot inject `*` (only `Owner` can). This is structural prevention absent from AWS IAM's mutate-policy primitive (`iam:CreatePolicyVersion`, which honours any actions the caller writes). Verified experimentally with identical infrastructure differing only in the calling role. Not documented in Microsoft's public RBAC reference.

- **D-Z4-03 (Azure token-binding vs AWS credential propagation)**. Azure AD access tokens carry permission claims established at issuance. Post-mutation permission changes do not propagate to in-flight tokens; a fresh IMDS token must be acquired. AWS in-flight STS credentials propagate IAM changes near-immediately (short eventual consistency). Detection implication: the same-MI sequence `roleDefinitions/write` → fresh IMDS token → control-plane write is a high-confidence Z4 signature.

- **D-Z2-01 / D-Z1-02 (institutional tenant constraints)**. AAD application registration is disabled by UNSW's tenant policy, forcing a two-subscription Azure layout. Z1 uses the UNSW subscription with the attacker modelled as a compromised user; Z2–Z8 use a personal MSA subscription where SP creation is permitted. Each scenario remains self-contained; attack chains are subscription-invariant.

## Detection Primitives (Convergence Refinement)

The catalogue is structured around defender-relevant convergence points rather than per-path detection. The **midway report claimed 8 AWS paths → 4 detection primitives (2:1 compression)**. During Z4 verification, the IAM-modification class was found to split into two structurally distinct primitives with different event surfaces and different detection signatures. The refined mapping is **8 AWS paths → 5 primitives (1.6:1 compression)** — a small loss in headline compression, but semantically lossless: no primitive collapses two independently-preventable attack classes.

| Primitive | AWS paths | Azure paths | Compression |
|---|---|---|---|
| 01 — IMDS extraction | P1, P2, P6 | Z1, Z8 | 3:1 |
| 02 — IAM modification (assign) | P5 | Z3 | 1:1 |
| 03 — IAM modification (mutate) | P3 | Z4 | 1:1 |
| 04 — Credential discovery | P7, P8 | Z2, Z5, Z6 | 2:1 |
| 05 — Trust topology | P4 | Z7 | 1:1 |

Rationale for the assign-vs-mutate split (previously merged into "IAM policy modification"):

- **Assign primitive** (`iam:AttachUserPolicy` / `roleAssignments/write`) — binds an existing policy or role definition to a new principal. Affects one principal at a time. Creates a new IAM record; visible in role-assignment audits.
- **Mutate primitive** (`iam:CreatePolicyVersion` / `roleDefinitions/write`) — rewrites the actions inside an existing policy or role definition. Affects **every** existing assignee retroactively. Creates no new IAM record; **invisible** to role-assignment audits, requires role-definition audits.

Different event surfaces, different detection queries, different forensic signatures. Treating them as one primitive collapses two independently-detectable signals.

Defender-output design (CloudTrail Lake queries + SCP snippets + baseline-aware joins) is developed cross-path in the primitive module (`attacks/_defender_output/`), not duplicated per path.

## Repository Layout
pathtriage/
├── environments/
│   ├── baseline/                          # AWS shared infra
│   ├── baseline_azure/                    # Azure UNSW-tenant baseline (Z1)
│   ├── baseline_azure_personal/           # Azure personal-MSA baseline (Z2-Z8)
│   └── scenarios/
│       ├── 01_passrole/ ... 08_s3_credential_harvest/
│       ├── Z1_vm_managed_identity/
│       ├── Z2_sp_credential_theft/
│       ├── Z3_role_assignment_manipulation/
│       └── Z4_custom_role_definition_abuse/
├── attacks/
│   ├── 01_passrole/ ... 08_s3_credential_harvest/    # AWS PoCs
│   ├── Z1_vm_managed_identity/ ... Z4_*/             # Azure PoCs
│   └── _defender_output/                             # detection primitives (in build)
│       ├── README.md
│       ├── PLAN.md
│       ├── methodology/
│       └── primitives/01_imds_extraction/ ... 05_trust_topology/
├── pathtriage/                            # Python package (CLI + enumerators + graph)
├── midway/                                # midway report + supporting documents
└── docs/

## Reproducing a Single Attack Path

```bash
# AWS example (path 01)
cd environments/scenarios/01_passrole
terraform init && terraform apply -auto-approve
cd ../../../attacks/01_passrole
python3 exploit.py --tf-output ../../environments/scenarios/01_passrole/output.json

# Azure example (Z4)
cd environments/scenarios/Z4_custom_role_definition_abuse
terraform init && terraform apply -auto-approve
# (see README in the attack directory for the full VM-side execution flow)
```

Each attack directory (`attacks/<id>/README.md`) contains full deployment, execution, expected output, and cleanup steps.

## Timeline

- **T1 2026**: AWS catalogue (P1–P8) verified
- **T2 W1–W5**: Midway report, Z1 verified, prototype `pathtriage scan` skeleton, exploitability rubric v1
- **T2 W6 (current)**: Z2–Z4 verified ✅; defender-output module methodology committed; Z5–Z6 next
- **T2 W7**: Z7–Z8 verified; AWS defender-output primitives 01–05 built and evaluated
- **T2 W8**: Azure defender-output equivalents (KQL); rubric calibration against measured TP/FP
- **T2 W9**: Final report, presentation
- **T3 (COMP9302)**: AI-agent IAM attack paths (out of scope for T2 report)

## References

- MITRE ATT&CK for Cloud (T15xx, T10xx family)
- CIS AWS Foundations Benchmark v3.0
- Related work comparison (Cloudsplaining, Prowler, Datadog CloudSIEM, Sigma HQ) — documented in `attacks/_defender_output/methodology/related_work.md`
