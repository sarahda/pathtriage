# Azure Detection Evaluation

Companion to `attacks/_defender_output/evaluation/evaluation_report.md`, which
covers the AWS side. This document records the Azure evaluation: what was
measured, how, and what the figures do and do not support.

---

## Why this is a separate exercise

The Technical Report notes that an Azure evaluation harness needs three things
the AWS one did not: a second corpus generator in Activity Log format, two
correlated log streams rather than one, and an execution path for KQL. Each of
those is addressed below.

**Two streams.** Finding 6 records that AWS CloudTrail carries
`sessionContext.sessionIssuer` on every `AssumedRole` call, so a role chain can
be rebuilt from one log. Azure's Activity Log has no equivalent field; the same
reconstruction requires joining Entra sign-in records against resource
operations. The generator therefore emits both streams with consistent
identities, timestamps and address anchors, so that a query joining them has
something coherent to join.

**KQL.** The primitives are authored in KQL, under
`primitives/*/azure_query.kql`. DuckDB does not execute KQL, so the harness
runs SQL translations that apply the same conditions to the same fields. This
mirrors the AWS arrangement, where committed CloudTrail Lake SQL is translated
for DuckDB; Section 9.2 of the Technical Report records why. A translation is
not the original, and this is stated again under *Limitations* below.

---

## Corpus

| | |
|---|---|
| Benign Activity Log events | 700,000 |
| Benign Entra sign-in events | 38,603 |
| Attack events (Z1–Z8) | 25 (17 activity, 8 sign-in) |
| **Total** | **738,628** |
| Window | 7 days, 2026-06-30 to 2026-07-06 |
| Seed | 42 |

Generated with:

```bash
python3 methodology/generate_azure_baseline.py \
    --rate 100000 --days 7 --seed 42 \
    --start-date 2026-06-30 --version 2026-08-02-1 \
    --activity-output corpora/azure_activity_baseline.jsonl \
    --signin-output   corpora/azure_signin_baseline.jsonl

python3 methodology/generate_azure_positive.py \
    --seed 42 --start-date 2026-06-30 --version 2026-08-02-1 \
    --activity-output corpora/azure_activity_positive.jsonl \
    --signin-output   corpora/azure_signin_positive.jsonl
```

Both generators require `--start-date` and `--version` and derive no default
from the run date. This is a deliberate departure from the AWS generator, whose
date-derived defaults mean a run today does not reproduce the bytes of a run in
July. The Azure generators reproduce byte-for-byte on any day:

```
activity baseline  sha256  004133d181c8a24650415bb1ac0387a64007eed18d483d02e35514815bb78ea0
signin   baseline  sha256  9869a4e9cdcd1f75268ddd7e4c3ada1d8e63d290f3de1710d4e801547a475ec6
```

The benign corpus is 833 MB and is not committed. The attack corpus is 28 KB
and is, at `evaluation/azure_activity_positive.jsonl` and
`evaluation/azure_signin_positive.jsonl`.

### Category shares

Matched to the AWS generator in proportion so the two corpora are comparable in
shape; the operations are Azure's.

| Category | Share | Contents |
|---|---|---|
| `read_heavy_browse` | 40% | portal and CLI reads by human operators |
| `cicd_deployment` | 25% | service-principal deployments, in bursts |
| `storage_access` | 15% | blob operations and `listKeys` |
| `rbac_admin` | 8% | role assignment and definition writes |
| `compute_lifecycle` | 7% | VM start/stop/restart, `runCommand` |
| `long_tail` | 5% | metrics, workspaces, Key Vault reads |

---

## Results

| Primitive | Paths | TP | Benign FP | Cross-path FP | Precision | Attack recall | MTTD |
|---|---|---|---|---|---|---|---|
| 01 IMDS extraction | Z1, Z8 | 5 | 0 | 2 | 1.000 | 1.000 | 7.0 s |
| 02 IAM mod (assign) | Z3 | 1 | 0 | 0 | 1.000 | 1.000 | 0.0 s |
| 03 IAM mod (mutate) | Z4 | 1 | 0 | 0 | 1.000 | 1.000 | 0.0 s |
| 04 Credential discovery | Z2, Z5, Z6 | 3 | 0 | 0 | 1.000 | 1.000 | 0.0 s |
| 05 Trust topology | Z7 | 1 | 0 | 0 | 1.000 | 1.000 | 0.0 s |

**Aggregate**

| Metric | Value |
|---|---|
| Macro precision | 1.000 |
| Macro attack-level recall | 1.000 |
| Macro event-level recall | 0.600 |
| Paths detected | 8 / 8 |
| Macro MTTD | 1.4 s |

All three pre-registered gates pass: precision ≥ 0.95, attack recall = 1.0,
median MTTD ≤ 60 s.

### The number that matters

Of the 700,000 benign Activity Log events, **107,683 carry a pattern one of the
primitives keys on**:

| Pattern | Benign events |
|---|---|
| Managed-identity operations | 38,435 |
| Role assignment writes | 25,385 |
| Role definition writes | 11,206 |
| Credential-surface reads | 32,657 |

None of them fired. That is the Azure analogue of the 122,479 figure on the AWS
side, and it is the claim that bears on whether these queries are deployable:
five true positives is a statement about the attack, a hundred thousand correct
non-fires is a statement about the rest of the week.

### Two false positives worth naming

Primitive 01 fires on two events that belong to Z3 and Z4. They are attack
events, so they are not benign false positives — the alert is correct and the
attribution is not. The harness reports these separately from benign false
positives, because collapsing them into one precision figure would hide which
kind of mistake the primitive makes. A defender paged by either alert would be
right to look.

---

## Event-level recall of 0.600

As on the AWS side, this is a design consequence rather than a shortfall. The
primitives fire on the exploitation event of a path, not on every step. For Z3,
Z4, Z5 and Z7 the follow-on write that exercises the newly obtained authority
is inside the truth set but is deliberately not a firing target: it is ordinary
control-plane traffic that only reads as malicious in light of the step before
it.

Sign-in records are excluded from the truth set entirely. They are context the
queries join against, not rows a query returns, and counting them as missed
detections would understate recall for a reason that has nothing to do with
detection quality.

---

## What was fixed during evaluation

Three defects surfaced when the primitives were first run, in the same class as
the AWS primitive-01 incident recorded in Chapter 9 of the Technical Report.

**Primitive 05 matched 37,523 events.** The cascade query joined a role grant
against any subsequent write inside the window, rather than against a write by
the principal that had been granted. The Activity Log records the grantee in
`properties.principalId`; the generator was not emitting it, so there was
nothing to join on. Adding the field and keying the join to it reduced the
match set to one.

**Primitive 03 matched 682 events.** The persistence gate accepted any
follow-on write by the same caller. Benign role-definition maintenance is
performed by human administrators who then do other work, so the gate matched
routine activity. Adding a baseline join — the caller must have no history of
role-definition writes — brought it to one.

**Primitive 04 matched 46 events.** The correlation between a credential read
and a new service-principal sign-in fired whenever any benign read fell within
thirty minutes of an attack sign-in, which at this corpus size is often. The
same baseline join applied: the reader must have no history of that operation.

None of these was visible from reading the queries. All three were found by
running them against a corpus large enough for the loose conditions to matter,
which is the argument for having a corpus at all.

---

## Limitations

**The evaluated queries are translations.** The committed KQL was not executed
against a Log Analytics workspace. What this evaluation establishes is that the
detection logic separates these attack events from this benign traffic; it does
not establish that the KQL runs correctly in Sentinel, and no tenant was
available to test that.

**The corpus is synthetic and its noise is the author's.** The same limitation
applies to the AWS corpus and is stated in the Technical Report. Real Azure
tenant traffic is more varied than anything designed here, and a primitive that
is precision-safe against generated traffic has not been shown to be
precision-safe in production.

**The attack corpus is derived from the verification logs, not captured from
Azure.** Each Z-path sequence is rendered from the first-party execution log in
`attacks/Z*/verification_log.txt`, which records the attacker's own output
rather than the Activity Log entries the actions produced. Field values the log
does not settle — user agents, correlation ids — are synthesised. The sequences
and their timings follow the logs; the log records themselves are reconstructed.

**Eight paths, one observer.** The catalogue limitations in Section 6.7 of the
Technical Report apply here unchanged.

---

## Reproducing

```bash
cd attacks/_defender_output

# 1. Generate the corpora (benign is 833 MB and not committed)
python3 methodology/generate_azure_baseline.py \
    --rate 100000 --days 7 --seed 42 \
    --start-date 2026-06-30 --version 2026-08-02-1 \
    --activity-output evaluation/corpora/azure_activity_baseline.jsonl \
    --signin-output   evaluation/corpora/azure_signin_baseline.jsonl

# 2. Confirm the generator produced the same bytes
shasum -a 256 evaluation/corpora/azure_activity_baseline.jsonl
# expect: 004133d181c8a24650415bb1ac0387a64007eed18d483d02e35514815bb78ea0

# 3. Run the evaluation
cd evaluation && python3 run_azure_evaluation.py
```

Requires `duckdb>=0.10`.
