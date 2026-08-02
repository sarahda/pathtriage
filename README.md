# PathTriage

Exploitability-ranked IAM attack-path discovery and defender-output synthesis for AWS and Azure.

## Demo

Five demonstration videos are attached to
[release v1.0](https://github.com/sarahda/pathtriage/releases/tag/v1.0):
the exploit chain, the detection run over 700,023 events, the coverage
gap, and both arms of the Azure Z4 privilege-escalation guard.


## Status

✅ **Complete** — COMP9301 2026

- **Midway report submitted** — verified catalogue, rubric v1, prototype design (June 2026)
- **AWS arm complete** — 8 / 8 paths verified end-to-end ✅
- **Azure arm complete** — 8 / 8 paths verified end-to-end ✅
- **Catalogue total** — 16 / 16 paths verified
- **Tool**: `pathtriage scan | discover | rank | detail` — IAM enumeration, BFS path discovery, and rubric-based ranking, with an offline fixture mode (Azure enumerator: catalogue documented, integration deferred)
- **Defender-output module**: methodology + 5 primitives committed (`attacks/_defender_output/`); evaluation complete — macro precision 1.000, attack-level recall 1.000, mean MTTD 9.2 s over a 700,023-event corpus

---

## Quick start

No cloud credentials are required for the test suite, the fixture-mode CLI, or the detection evaluation.

### Option A — Docker (recommended)

```bash
git clone https://github.com/sarahda/pathtriage.git
cd pathtriage
docker build -t pathtriage .
docker run --rm pathtriage
```

The default command runs the unit test suite, so a successful `docker run` is itself evidence that the environment is correctly provisioned. Expect **10 passed**.

For the reproduction steps below, open a shell in the image:

```bash
docker run --rm -it pathtriage bash
```

### Option B — local install

Requires Python 3.11 or later.

```bash
git clone https://github.com/sarahda/pathtriage.git
cd pathtriage
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[evaluation]"
pytest -v          # expect: 10 passed
```

> The `[evaluation]` extra installs `duckdb`, which the detection harness requires. `pip install -e .` alone is sufficient for the CLI but not for the evaluation steps.

---

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

### Azure (8 / 8 verified)

| # | Path | Mechanism | Status |
|---|------|-----------|--------|
| Z1 | VM Managed Identity via IMDS | System-Assigned MI granted Contributor at subscription scope; IMDS token used off-box | ✅ Verified |
| Z2 | Service Principal Credential Theft | SP `clientSecret` leaked in App Service `app_settings`; MI reads via `Website Contributor` → OAuth2 `client_credentials` → subscription Contributor | ✅ Verified |
| Z3 | Role Assignment Manipulation | `Microsoft.Authorization/roleAssignments/write` (via UAA) → self-grant Owner on RG | ✅ Verified |
| Z4 | Custom Role Definition Abuse | `Microsoft.Authorization/roleDefinitions/write` (via Owner) → inject wildcard `*` into custom role `actions[]`, retroactive elevation of all assignees | ✅ Verified |
| Z5 | Key Vault Secret Escalation | MI reads SP secret from Key Vault via RBAC (Secrets User) → OAuth2 client_credentials → subscription Contributor | ✅ Verified |
| Z6 | Storage Account Key Abuse | MI `listKeys` → account key → SharedKey blob GET (bypasses AAD) → parse tfstate → embedded SP creds → subscription Contributor | ✅ Verified |
| Z7 | MI / SP Chain (Role Cascade) | SP-A (UAA on RG) grants Contributor to SP-B → SP-B token → subscription-level write via cascade | ✅ Verified |
| Z8 | VM Run Command Abuse | MI-A (narrow `runCommand` custom role) → root shell on VM-B → MI-B token (subscription Contributor) exfiltrated via response body | ✅ Verified |

Azure paths Z2–Z8 are deployed on a separate personal-MSA subscription; Z1 remains on the UNSW Azure for Students subscription. Rationale documented in `attacks/Z2_sp_credential_theft/README.md` (D-Z2-01) — the UNSW tenant policy disables application registration, blocking any Azure path that requires Service Principal creation.

---

## Key Findings

Documented per-path in the individual READMEs; the ones with material contribution to the AWS↔Azure comparative analysis are summarised here.

### Structural asymmetries (AWS lacks / Azure lacks)

- **D-Z4-02 (undocumented Azure RBAC privilege-escalation guard)**. Azure silently reverts role-definition mutations whose new `actions[]` contain actions the calling principal does not already hold. A `PUT` returns 200 OK with the echoed body, but a backend validator reverts the persisted state within seconds. `User Access Administrator` cannot inject `*` (only `Owner` can). This is structural prevention absent from AWS IAM's mutate-policy primitive (`iam:CreatePolicyVersion`, which honours any actions the caller writes). Verified experimentally with identical infrastructure differing only in the calling role. Not documented in Microsoft's public RBAC reference.

- **D-Z6-01 (Storage Account Key Operator: no data-plane RBAC, full data-plane authority)**. The built-in `Storage Account Key Operator Service Role` grants only `listKeys/action` and `regenerateKey/action` — visible as control-plane-only in RBAC audits. But the returned account keys authenticate directly against Azure Storage's shared-key auth scheme, which bypasses AAD and RBAC entirely. The identity is functionally a data-plane owner in disguise. AWS S3 has never supported shared-key auth — all access requires IAM authentication. This makes Z6 detection strictly harder than AWS P8: it requires correlating two log sources (Activity Log `listKeys` + storage diagnostic SharedKey events, the latter off by default), whereas P8 is a single CloudTrail event.

- **D-Z7-02 (Azure OBO structurally blocks pure SP-to-SP chained impersonation)**. Initial Z7 approach was OAuth 2.0 On-Behalf-Of flow as the direct semantic equivalent of AWS `sts:AssumeRole` chained impersonation. Azure returned `AADSTS500131`: the OBO assertion audience must be the client app presenting the assertion, and that audience only exists in user-delegation flows (post user sign-in). Pure `client_credentials` cannot produce such tokens. **Azure's identity platform prevents an entire attack class from AWS P4 at design time.** Pivoted to role-assignment cascade (authorization-level chain) — same primitive class, different mechanic. Detection surfaces differ: AWS P4 is a sequence pattern on CloudTrail; Azure Z7 is a two-source correlation across Activity Log + AAD SignInLogs.

### Behavioural asymmetries

- **D-Z4-03 (Azure token-binding vs AWS credential propagation)**. Azure AD access tokens carry permission claims established at issuance. Post-mutation permission changes do not propagate to in-flight tokens; a fresh IMDS token must be acquired. AWS in-flight STS credentials propagate IAM changes near-immediately. Detection implication: the same-MI sequence `roleDefinitions/write` → fresh IMDS token → control-plane write is a high-confidence Z4 signature.

- **D-Z7-03 (role assignment propagation gap)**. Azure role assignments created via `roleAssignments/write` return 201 immediately but require 30–60 seconds for propagation to the token validation layer. AWS role assignments propagate essentially instantly. The Azure propagation gap is itself a detection window: grant event → temporal gap → subsequent SP sign-in from the granted identity is a signature the AWS analogue does not have.

- **D-Z8-02 (runCommand response envelope permits token exfiltration in-band)**. Azure VM `runCommand` returns stdout+stderr up to ~4KB in the response body — sufficient to exfiltrate a full Managed Identity token (~1800 chars). No external network channel needed from the target VM. AWS `ssm:SendCommand` returns command output through a distinct mechanism (SSM inventory) with different logging and different network paths. This makes Z8 attribution harder post-hoc: no persistent artifact beyond the runCommand event itself.

### Institutional / environmental

- **D-Z2-01 / D-Z1-02 (institutional tenant constraints)**. AAD application registration is disabled by UNSW's tenant policy, forcing a two-subscription Azure layout. Z1 uses the UNSW subscription with the attacker modelled as a compromised user; Z2–Z8 use a personal MSA subscription where SP creation is permitted. Each scenario remains self-contained; attack chains are subscription-invariant.

- **D-Z7-01 (cloud-init unreliable for secret injection on Azure Linux VMs)**. Azure Linux VMs create the admin SSH user via the Azure Guest Agent (waagent), not via cloud-init's `users` module. Cloud-init `write_files` runs before waagent completes user provisioning, so files owned by the admin user fail with "user not found". This also leaves `/home/azureuser` in an inconsistent ownership state (root-owned), blocking subsequent SSH-based writes until an explicit `chown`. Two-step deployment (terraform apply + credential SCP) documented as the reliable pattern.

---

## Detection Primitives (Convergence Refinement)

The catalogue is structured around defender-relevant convergence points rather than per-path detection. The **midway report claimed 8 AWS paths → 4 detection primitives (2:1 compression)**. During Z4 verification, the IAM-modification class was found to split into two structurally distinct primitives with different event surfaces and different detection signatures. The refined mapping is **8 AWS paths → 5 primitives (1.6:1 compression)** — a small loss in headline compression, but semantically lossless: no primitive collapses two independently-preventable attack classes.

Extending to the full 16-path catalogue:

| Primitive | AWS paths | Azure paths | Compression |
|---|---|---|---|
| 01 — IMDS extraction | P1, P2, P6 | Z1, Z8 | 5 → 1 (5:1) |
| 02 — IAM modification (assign) | P5 | Z3 | 2 → 1 (2:1) |
| 03 — IAM modification (mutate) | P3 | Z4 | 2 → 1 (2:1) |
| 04 — Credential discovery | P7, P8 | Z2, Z5, Z6 | 5 → 1 (5:1) |
| 05 — Trust topology | P4 | Z7 | 2 → 1 (2:1) |

**16 paths → 5 primitives (3.2:1 average compression across both clouds).** The compression improves substantially when Azure paths are included because Azure exercises the same primitives through different discovery/execution surfaces than AWS — the primitives are cloud-invariant even where the specific queries and preventive controls are cloud-specific.

Rationale for the assign-vs-mutate split (previously merged into "IAM policy modification"):

- **Assign primitive** (`iam:AttachUserPolicy` / `roleAssignments/write`) — binds an existing policy or role definition to a new principal. Affects one principal at a time. Creates a new IAM record; visible in role-assignment audits.
- **Mutate primitive** (`iam:CreatePolicyVersion` / `roleDefinitions/write`) — rewrites the actions inside an existing policy or role definition. Affects **every** existing assignee retroactively. Creates no new IAM record; **invisible** to role-assignment audits, requires role-definition audits.

Different event surfaces, different detection queries, different forensic signatures. Treating them as one primitive collapses two independently-detectable signals.

Defender-output design (CloudTrail Lake queries + SCP snippets + baseline-aware joins) is developed cross-path in the primitive module (`attacks/_defender_output/`), not duplicated per path. Evaluation execution is complete — see `attacks/_defender_output/evaluation/`.

---

## Repository Layout

```text
pathtriage/
├── Dockerfile                                # reproducible environment
├── environments/
│   ├── baseline/                             # AWS shared infra
│   ├── baseline_azure/                       # Azure UNSW-tenant baseline (Z1)
│   ├── baseline_azure_personal/              # Azure personal-MSA baseline (Z2-Z8)
│   └── scenarios/
│       ├── 01_passrole/ ... 08_s3_credential_harvest/
│       ├── Z1_vm_managed_identity/
│       ├── Z2_sp_credential_theft/
│       ├── Z3_role_assignment_manipulation/
│       ├── Z4_custom_role_definition_abuse/
│       ├── Z5_kv_secret_escalation/
│       ├── Z6_storage_account_key_abuse/
│       ├── Z7_mi_sp_chain/
│       └── Z8_vm_run_command_abuse/
├── attacks/
│   ├── 01_passrole/ ... 08_s3_credential_harvest/    # AWS PoCs
│   ├── Z1_vm_managed_identity/ ... Z8_*/             # Azure PoCs
│   └── _defender_output/                             # detection primitives
│       ├── README.md
│       ├── PLAN.md
│       ├── methodology/                              # corpus generators + protocol
│       ├── evaluation/                               # corpora, harness, results
│       └── primitives/
│           ├── 01_imds_extraction/
│           ├── 02_iam_mod_assign/
│           ├── 03_iam_mod_mutate/
│           ├── 04_credential_discovery/
│           └── 05_trust_topology/
├── pathtriage/                               # Python package (CLI + enumerators + graph)
├── tests/                                    # unit tests
├── report/                                   # Technical Report sources + rubric validation
├── midway/                                   # midway report + supporting documents
└── docs/
```

---

## Reproducing the results

Every quantitative claim in the Technical Report can be regenerated from a clean clone. Steps 1–5 run entirely offline.

### 1. Path discovery and ranking (offline)

```bash
python3 -m pathtriage discover --fixture pathtriage/fixtures/aws_catalogue_sample.json --limit 10
python3 -m pathtriage rank     --fixture pathtriage/fixtures/aws_catalogue_sample.json --limit 10
```

`rank` orders the discovered paths under rubric v1 with weights 0.30 / 0.20 / 0.30 / 0.20. Weight rationale and per-input definitions are in the Technical Report, Chapter 8.

### 2. The evaluation corpus

The benign corpus is 591 MB, past what GitHub will hold, so it is
generated rather than committed:

```bash
python3 attacks/_defender_output/methodology/generate_baseline.py \
    --rate 100000 --days 7 --seed 42 \
    --start-date 2026-06-30 --version 2026-07-17-1 \
    --account-id 559292738121 \
    --output attacks/_defender_output/evaluation/corpora/baseline_reference.jsonl
```

The attack corpus is small and is committed at
`corpora/positive_corpus.jsonl` — 23 labelled events across the eight
AWS paths.

The SHA-256 values quoted in the Technical Report record the exact
input the reported figures were computed from on 17 July. A run today
does not reproduce those bytes, so treat them as provenance rather
than as a checksum to match. What does reproduce is the evaluation
itself. Running the harness against a freshly generated baseline plus
the committed attack corpus returns the same aggregate figures —
macro precision 1.000, attack-level recall 1.000, mean MTTD 9.2 s —
which is a stronger result than byte equality would be, since the
benign traffic differs.

### 3. Re-run the detection evaluation

```bash
cd attacks/_defender_output/evaluation
python3 run_evaluation.py
cd -

jq '.aggregate, .coverage_gate' \
   attacks/_defender_output/evaluation/results/primitive_evaluation.json
```

Expected, matching the Technical Report, Chapter 7:

| Metric | Value |
|---|---|
| Macro precision | 1.000 |
| Attack-level recall | 1.000 |
| Event-level recall | 0.611 |
| Mean MTTD | 9.2 s |
| Paths detected | 8 / 8 |

All three pre-registered gates (`all_precision_ge_0.95`, `all_attack_recall_1.0`, `median_mttd_le_60`) should report `true`.

> **Note on determinism.** The aggregate figures above are stable across
> runs. The `tp_events` and `fn_events` arrays inside
> `primitive_evaluation.json` may list the same events in a different
> order, and where several events satisfy a primitive's conditions
> equally the specific event IDs recorded can differ: the detection
> queries do not impose a total ordering, so DuckDB is free to return
> qualifying rows in any order. Counts, precision, recall and MTTD are
> unaffected. Compare aggregates rather than diffing the file
> byte-for-byte.

Per-primitive figures:

```bash
jq -r '.per_primitive | to_entries[] |
  "primitive \(.key)  paths=\(.value.covered_paths|join(","))  TP=\(.value.tp)  FP=\(.value.fp)  precision=\(.value.precision)  mttd=\(.value.mttd_mean_sec)s"' \
  attacks/_defender_output/evaluation/results/primitive_evaluation.json
```

### 4. Rubric validation (optional)

```bash
pip install scipy numpy matplotlib
python3 report/rubric_validation/cvss_comparison.py
```

Reproduces the CVSS cross-comparison (Spearman ρ) and the scatter plot used in Chapter 8.

### 5. Reproducing a single attack path (requires cloud credentials)

This step deploys real infrastructure into your own account and will incur cost. Tear down with `terraform destroy` when finished.

```bash
# AWS example (path 01)
cd environments/scenarios/01_passrole
terraform init && terraform apply -auto-approve
terraform output -json > output.json
cd ../../../attacks/01_passrole
python3 exploit.py --tf-output ../../environments/scenarios/01_passrole/output.json
```

```bash
# Azure example (Z4)
cd environments/scenarios/Z4_custom_role_definition_abuse
terraform init && terraform apply -auto-approve
terraform output -json > output.json
# Z4 executes from the VM itself; see the attack README for the SSH flow
```

Each attack directory (`attacks/<id>/README.md`) contains full deployment, execution, expected output, and cleanup steps.

### What this does *not* reproduce

Two things in the Technical Report cannot be regenerated from this repository alone.

**The attack-path executions.** The sixteen verification logs in `attacks/*/verification_log.txt` were captured against live AWS and Azure accounts. The Terraform is committed and the per-path READMEs document the expected output, but the logs themselves are evidence of past runs, not something this repository can replay.

**CloudTrail Lake execution.** The detection primitives are authored in CloudTrail Lake SQL. The evaluation above runs a DuckDB translation of the same queries against a local corpus, which is what makes it free and reproducible. Validation against a live CloudTrail Lake feed has not been performed and is listed as future work in the Technical Report.

---

## References

- MITRE ATT&CK for Cloud (T15xx, T10xx family)
- CIS AWS Foundations Benchmark v3.0
- Rhino Security Labs — AWS IAM Privilege Escalation Methods
- Related work comparison (Cloudsplaining, Prowler, Datadog CloudSIEM, Sigma HQ) — documented in `attacks/_defender_output/methodology/related_work.md`

## Licence

MIT — see [LICENSE](LICENSE).

Deliberately vulnerable infrastructure is provided for security research and education. Deploy only into isolated accounts you control, and tear it down when finished.
