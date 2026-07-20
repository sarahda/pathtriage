# D-Z Decision Log Map

Auto-generated from grep across attack path READMEs (2026-07-19).
Cross-reference for Section 4 headline findings during report drafting.

## Per-path D-Z references

| Path folder | D-Z log references | Files containing D-Z |
|---|---|---|
| 01_passrole | (none) | — |
| 02_imds_ssrf | (none) | — |
| 03_createpolicyversion | (none) | — |
| 04_assume_role_chain | (none) | — |
| 05_attachpolicy | (none) | — |
| 06_instance_profile | (none) | — |
| 07_lambda_env_theft | (none) | — |
| 08_s3_credential_harvest | (none) | — |
| Z1_vm_managed_identity | (none) | — |
| Z2_sp_credential_theft | D-Z1-02, D-Z2-01 | README.md |
| Z3_role_assignment_manipulation | D-Z2-01 | README.md |
| Z4_custom_role_definition_abuse | D-Z2-01, D-Z4-01, D-Z4-02, D-Z4-03, D-Z4-04, D-Z4-05 | README.md |
| Z5_kv_secret_escalation | D-Z2-01, D-Z4-04, D-Z5-01 | README.md |
| Z6_storage_account_key_abuse | D-Z2-01, D-Z4-04, D-Z6-01, D-Z6-02 | README.md |
| Z7_mi_sp_chain | D-Z2-01, D-Z4-04, D-Z7-01, D-Z7-02, D-Z7-03 | README.md |
| Z8_vm_run_command_abuse | D-Z2-01, D-Z4-04, D-Z7-03, D-Z8-01, D-Z8-02, D-Z8-03 | README.md |

## Section 4 headline finding cross-reference

For the 6 Section 4 headline findings, where to cite:

### D-Z4-02 (Structural asymmetry — custom role definition)
- README.md
- report/chapter1_motivation_outline.md
- attacks/Z4_custom_role_definition_abuse/README.md
- attacks/_defender_output/README.md
- attacks/_defender_output/PLAN.md

### D-Z4-03
- README.md
- attacks/Z4_custom_role_definition_abuse/README.md
- attacks/_defender_output/README.md
- attacks/_defender_output/methodology/related_work.md
- attacks/_defender_output/primitives/03_iam_mod_mutate/azure_symmetry.md

### D-Z6-01 (Storage Account Key Operator RBAC gap)
- README.md
- report/chapter1_motivation_outline.md
- attacks/Z6_storage_account_key_abuse/README.md
- attacks/_defender_output/primitives/04_credential_discovery/azure_symmetry.md

### D-Z7-02 (Azure OBO structurally blocks SP-to-SP chain — Midnight Blizzard adjacent)
- README.md
- report/chapter1_breach_notes.md
- attacks/Z7_mi_sp_chain/README.md
- attacks/_defender_output/primitives/05_trust_topology/azure_symmetry.md

### D-Z7-03
- README.md
- attacks/Z7_mi_sp_chain/README.md
- attacks/Z8_vm_run_command_abuse/README.md
- attacks/_defender_output/primitives/05_trust_topology/azure_symmetry.md

### D-Z8-02
- README.md
- attacks/Z8_vm_run_command_abuse/README.md
- attacks/_defender_output/primitives/01_imds_extraction/azure_symmetry.md

## Notes for report drafting

- **AWS paths lack D-Z logs** — decision provenance for AWS attacks is
  embedded in each path's README rather than tagged with D-P/D-A codes.
  When Section 4 needs to cite an AWS-side design decision, reference
  the path README directly (e.g., `attacks/03_createpolicyversion/README.md`
  §"Design rationale").
- **Z2_sp_credential_theft carries D-Z1-02** — this cross-Z reference
  suggests a shared decision between Z1 and Z2 documented in Z2's
  README. Worth verifying when writing §4 on structural asymmetries.
- **D-Z2-01 appears in 7 of 8 Azure paths** — this looks like a
  foundational Azure decision (probably about how RBAC roles are
  scoped or how the labs are provisioned). Read it once and cite
  centrally, not per-path.
- **D-Z4-04 appears in 5 paths (Z5–Z8)** — same pattern, likely a
  cross-cutting decision about custom role definitions.
