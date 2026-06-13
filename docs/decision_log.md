# PathTriage Decision Log — W2 (8–15 June 2026)

> **Author:** Tessa Moon (z5660470)
> **Purpose:** Engineering audit trail of design decisions and plan deviations during COMP9301 Week 2. Each entry records the decision, the original plan position, the alternative options considered, and the chosen path forward — so that the Midway Report (W5) and external evaluators can trace *why* the W2 catalogue looks the way it does.

---

## Summary

W2 closed with **3 / 8 verified attack paths** (Paths 1, 2, 3 — all AWS) and a working `pathtriage scan --provider aws` skeleton. Two substantive deviations from the Day 1 W2 plan are recorded below (D-W2-01, D-W2-02). All other plan items completed as scoped.

---

## D-W2-01 — Path 3 implemented as **self-attach** variant (deviation)

**Plan reference:** Day 1 report §6.3 specified the *role variant*:
> "managed IAM policy where the low-priv user has `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` on a customer-managed policy attached to **a high-priv role** … validates escalation via `sts:GetCallerIdentity` **from a role-assuming session**."

**What was built:** the *self-attach variant*. The dangerous policy is attached to the **low-priv user themselves**, and escalation is validated by an `iam:CreateUser` before/after probe on the same identity (no role assumption hop).

**Alternatives considered:**

| Option | Description | Trade-off |
|---|---|---|
| A. Replace with role variant | Rebuild Terraform + PoC to match §6.3 exactly | Discards completed self-attach work; aligns with stated plan |
| B. Keep self-attach as Path 3 | Document deviation in this log | Faster path to 3/3 verified; honest narrative requires this entry |
| **C. Self-attach as Path 3 + role variant as Path 3b (chosen for now → revisit W3-4)** | Both variants in catalogue | Maximises catalogue diversity; Path 3b is a small delta on existing Path 3 |

**Chosen approach:** Option B for W2 close, **with Path 3b queued for W3-4** (small delta on existing Terraform/PoC; not a full new path effort).

**Rationale:**

1. **Catalogue diversity.** Paths 1 and 2 are both EC2/IMDS-based. The role variant of Path 3 would partially overlap Path 1's "land on a role" mechanic. Self-attach is the *purest user-level pure-IAM* primitive in the catalogue.
2. **Validation cleanliness.** Self-attach escalation is verified by a single before/after probe on one principal. The role variant requires an additional assume-role hop, which conflates two separate primitives (CreatePolicyVersion + role assumption) in the same PoC.
3. **Canonical reference.** Rhino Security Labs documents the self-attach variant as the canonical `CreatePolicyVersion` primitive.

**Risk and mitigation:**

- *Risk:* Deviation from approved scope could be read as undisciplined execution.
- *Mitigation:* This log entry; explicit "Design note — self-attach vs role variant" section in `attacks/03_createpolicyversion/README.md`; Path 3b queued as a defined deliverable rather than a vague intention.

> [!important] 한국어 메모 — Methodology rigour 학술 marking에서 *"계획과 다른 결정"*은 그 자체로 감점 사유가 아님. *기록되지 않은 deviation*이 감점 사유. 본 entry + README의 design note가 paired audit trail.

---

## D-W2-02 — Named AWS profile migration **deferred** to W3

**Plan reference:** Day 1 report §1.3 and §6.5 risk table both committed the migration "by Wed [11 June] before Path 2 verification." The env-var pattern was retained instead for all three W2 paths.

**Why deferred:**

- Path 2 + Path 3 verification time was the binding W2 constraint.
- The migration is a refactor with no per-path catalogue output and zero impact on the *correctness* of the W2 deliverables.
- Verification log + README discipline produced for Paths 1–3 explicitly document the `unset` / `export` sequence at each credential context boundary, so the underlying validity risk (§1.3) is currently controlled by *operational discipline + documentation* rather than *tooling*.

**Risk and mitigation:**

- *Risk:* Probability of credential bleeding compounds linearly with path count. By Path 6–8 the env-var pattern becomes a real reliability tax during demo / re-verification.
- *Mitigation:* Migration scheduled as the first task of W3 (target Mon 16 June), before any new path work begins. This log entry creates a hard commit.

---

## D-W2-03 — Defender output + exploitability scoring: deferred per design

**Status:** No change from plan. Per-path READMEs for Paths 1–3 mark these items as *deferred (W7 / W5)* rather than missing.

**Rationale recap (also in repo README):**

- Detection design at path granularity duplicates work — Paths 1, 2 (and projected Path 6) converge on the same IMDS-based extraction primitive. A *single* KQL/EQL rule covering the converged surface is more valuable than three near-duplicates.
- Exploitability scoring requires ≥5 paths to compare against the unified rubric. Scoring two or three paths in isolation does not exercise the rubric.

No deviation; this entry exists so that the absent sections in per-path READMEs are not later misread as gaps.

---

## D-W2-04 — PathTriage Python skeleton: HAS_POLICY edges only for W2

**Plan reference:** §6.4 W2 target — `pathtriage scan --provider aws` produces a non-empty graph.

**What was built:**

- `pathtriage/cli/main.py` — argparse + `scan` dispatch + optional `--output` GraphML export
- `pathtriage/enumerators/aws.py` — boto3 enumeration of users, roles (excluding service-linked), and customer-managed policies
- `pathtriage/graph/builder.py` — NetworkX `DiGraph` with `HAS_POLICY` edges from principals to attached managed policies

**Deferred to W3+:**

- *Reachability edges:* `PASS_ROLE` (principal → role via `iam:PassRole`), `CAN_ASSUME` (role trust policy), `ESCALATES_VIA` (matched primitive — the catalogue's link to the graph).
- *Inline policy expansion:* current enumerator lists inline policy *names* only; document expansion + statement-level matching land with the reachability edges.

**Real-AWS execution evidence:** see attached run log [TODO: paste output of `python3 -m pathtriage.cli.main scan --provider aws` against account 559292738121 here].

---

## D-W2-05 — Cosmetic: heredoc markers in Path 2 verification log

`attacks/02_imds_ssrf/verification_log.txt` includes `<<EOT … EOT` markers around the scenario summary because `terraform output scenario_summary` was used instead of `terraform output -raw scenario_summary`. Evidence integrity is unaffected (the captured exploit run is the verification artefact, the summary is contextual framing).

**Decision:** leave as-is for Path 2; standardise on `-raw` for Paths 3+. Path 3 verification capture uses `-raw`. No re-capture warranted.

---

## D-W2-06 — Repository hygiene additions

Added during W2 close:

- `LICENSE` — MIT, matching the existing repo README link
- `requirements.txt` — pins `boto3`, `networkx`, `requests` for external reproducers
- `pyproject.toml` — already created with the skeleton; `pip install -e .` performed in W2 so the `pathtriage` console script resolves as documented

These are reproducibility prerequisites (D4 marking dimension), not findings.

---

## W2 cost report

- AWS spend to W2 close: **$0** (within Free Tier)
- Promotional credit remaining: **$120** (valid to 8 December 2026)
- Notable: Path 2 leaves a `t3.micro` running between verification and `terraform destroy`. Cumulative hours used remain a small fraction of the 750/month Free Tier allowance.

---

## W3 entry tasks (carry-forward)

1. **Named profile migration** (D-W2-02 follow-up) — Mon 16 June
2. **Path 3b — role variant** (D-W2-01 follow-up) — small Terraform/PoC delta on existing Path 3
3. **Paths 4 and 5** per original W3 schedule
4. **Reachability edges in the graph builder** (D-W2-04 follow-up)

---

🌱 *End of W2 decision log. Next entry: W3 close.*
