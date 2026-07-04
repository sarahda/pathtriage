# PathTriage Defender-Output Module

## Purpose

This module converts PathTriage's verified attack catalogue into deployable detection queries and preventive controls, organised by **detection primitive** rather than by attack path. It answers three questions the attack catalogue alone cannot:

1. **How is each attack actually observable to a defender?** — CloudTrail Lake queries (AWS) with baseline-aware joins.
2. **How is each attack preventable?** — Service Control Policy (SCP) snippets and, where relevant, IAM condition guards.
3. **How well does the resulting detection work?** — measured true-positive rate, false-positive rate, mean-time-to-detect, and coverage against three community/commercial detection baselines.

The module intentionally does not enumerate one detection per attack path. It compresses the 8 AWS paths into **5 detection primitives** (a refinement of the midway report's 4 primitives — see §Convergence Refinement below), each of which detects one or more paths simultaneously. This design maximises signal-to-noise and minimises rule-maintenance burden.

## Convergence Refinement (8 → 5 primitives)

The midway report stated 8 → 4 convergence. During Z4 verification (see `attacks/Z4_role_definition_abuse/README.md` D-Z4-02), a structural difference between AWS `iam:CreatePolicyVersion` and `iam:AttachPolicy` was identified: the former mutates a policy that is already attached to identities (retroactive elevation of every principal holding that policy), the latter attaches an existing policy to a new identity (elevation of one principal). These are different ARM-event surfaces in Azure and different CloudTrail event surfaces in AWS. Treating them as one IAM-modification primitive collapses two independently-detectable signals and materially reduces coverage.

The refined mapping is therefore:

| Primitive | AWS paths | Azure paths (finalised in W8) | Compression |
|---|---|---|---|
| 01 — IMDS extraction | P1, P2, P6 | Z1, Z8 | 3:1 |
| 02 — IAM modification (assign) | P5 | Z3 | 1:1 |
| 03 — IAM modification (mutate) | P3 | Z4 | 1:1 |
| 04 — Credential discovery | P7, P8 | Z2, Z5, Z6 | 2:1 |
| 05 — Trust topology | P4 | Z7 | 1:1 |
| **Total AWS** | **8 paths** | | **5 primitives (1.6:1)** |

Compression drops from 2:1 (midway) to 1.6:1 (refined). The refined mapping is **lossless** with respect to detection: no single primitive collapses two independently-preventable attack classes. This is characterised in `methodology/evaluation_protocol.md` as an intentional trade-off — measured semantic accuracy over headline compression ratio.

## Module Structure

```
_defender_output/
├── README.md                          # this file
├── PLAN.md                            # 14-hour build schedule, deliverable checklist
├── methodology/
│   ├── evaluation_protocol.md         # TP/FP measurement, precision/recall definitions
│   ├── baseline_generation.md         # synthetic benign CloudTrail event generator
│   ├── related_work.md                # Cloudsplaining / Prowler / Datadog / Sigma comparison
│   └── adversarial_evasion.md         # per-primitive evasion analysis framework
└── primitives/
    ├── 01_imds_extraction/            # covers P1, P2, P6
    ├── 02_iam_mod_assign/             # covers P5
    ├── 03_iam_mod_mutate/             # covers P3
    ├── 04_credential_discovery/       # covers P7, P8
    └── 05_trust_topology/             # covers P4
```

Each primitive directory contains (populated during build, per PLAN.md):

```
NN_<primitive_name>/
├── README.md                          # detection rationale, coverage claim
├── cloudtrail_lake_query.sql          # baseline-aware CTL query
├── scp_snippet.json                   # preventive SCP
├── paths.md                           # per-path signal, per-path signature
├── adversarial_evasion.md             # per-primitive evasion analysis
├── azure_symmetry.md                  # AWS↔Azure signal correspondence (design-only; KQL in W8)
└── evaluation.md                      # TP/FP results, precision/recall, MTTD
```

## Cross-Cloud Symmetry

Each AWS primitive is validated against the Azure catalogue via a **signal-correspondence check**: for the primitive to be admitted, an equivalent Azure signal must be identifiable (even if the KQL implementation is deferred to W8). This is a sanity check on primitive validity, not a duplication of the Azure-side defender-output work.

The Azure symmetry pages also document one asymmetry per primitive:

- **Prevention model**: AWS provides reactive detection; Azure sometimes provides service-side structural prevention (e.g., the privilege-escalation guard on `roleDefinitions/write`, per Z4 D-Z4-02).
- **Token semantics**: AWS in-flight STS credentials propagate IAM changes near-immediately; Azure MI/SP tokens are bound to permissions at issuance and require refresh (per Z4 D-Z4-03).

These asymmetries feed thesis Section 4's comparative analysis.

## Evaluation Design (Summary)

Each primitive is measured against three inputs:

1. **Positive traffic** — the verified attack labs (`attacks/0[1-8]_*/`), replayed to CloudTrail.
2. **Negative traffic** — synthetic benign CloudTrail events (`methodology/baseline_generation.md`), sized to approximate a small-to-medium enterprise's daily event rate (~100k events/day).
3. **Comparison baselines** — three existing open-source or commercial detection rule sets (`methodology/related_work.md`).

Reported metrics per primitive: precision, recall, F1, MTTD (mean time to detect), coverage-vs-baselines. See `methodology/evaluation_protocol.md`.

## Deliverables (14-hour build)

See `PLAN.md`. Summary:

- 5 primitives × 7 files each = 35 primitive-level files
- 4 methodology documents
- 1 aggregate evaluation report (`evaluation_report.md`, produced after all primitives are measured)

## References

The design draws on the following (full citations in `methodology/related_work.md`):

- Cloudsplaining (Salesforce) — IAM policy static analysis
- Prowler — cloud audit rules
- Datadog CloudSIEM — commercial baseline rules
- Sigma HQ cloud category — community rules
- MITRE ATT&CK for Cloud (T15xx, T10xx family)
- CIS AWS Foundations Benchmark v3.0
