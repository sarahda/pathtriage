# Adversarial Evasion — Framework

## Purpose

Each primitive detects a baseline attacker executing the verified attack as documented. This document specifies how each primitive's resistance to evasion is analysed. Evasion analysis is qualitative (not folded into the precision/recall metrics in `evaluation_protocol.md`) but is a required deliverable per primitive; it informs the report's discussion of detection robustness.

## 1. Threat model

### 1.1 Attacker capability assumed

The evasion analysis assumes an attacker with:

- Full read access to the PathTriage repository (worst-case, whitebox adversary)
- Ability to execute arbitrary AWS API calls with any credentials they have compromised
- Ability to time their actions arbitrarily (no online-defender constraints)
- No ability to modify CloudTrail delivery, log tampering, or CTL data-store contents (these are separate attack classes covered by CIS controls; out of scope here)

### 1.2 Attacker knowledge of detection

Three levels of adversarial knowledge:

- **Blind**: attacker does not know what detections exist. Baseline. Most real-world attackers.
- **Graybox**: attacker knows the general shape of detection (e.g., "there is IMDS-related monitoring") but not the specific rules.
- **Whitebox**: attacker has read the PathTriage repository and knows every query condition. Most conservative.

Per-primitive evasion analysis considers all three levels. Blind evasion is essentially attack success rate; graybox and whitebox are where the analysis has content.

### 1.3 Out-of-scope evasion classes

The following evasion classes are documented but not analysed per primitive:

- **Log tampering / suppression** — CloudTrail delivery to CTL is assumed intact. If an attacker can prevent log delivery, detection is impossible by definition; this is covered by CIS 3.x controls.
- **Time-shift evasion** — an attacker who spreads an attack over months to defeat lookback-window detection is a distinct threat class (persistent access rather than attack). Out of scope for baseline evasion analysis, but mentioned per primitive where relevant.
- **Data-plane evasion** — bypassing control-plane logging entirely by using data-plane paths (e.g., pre-signed URLs, VPC endpoints). This is worth thesis discussion; per-primitive analysis notes where a primitive is control-plane-only.
- **Insider evasion** — attacker uses legitimate credentials in legitimate patterns. This is baseline-anomaly-hardest; per-primitive analysis notes when a primitive relies on caller-history baseline that an insider can defeat by "warming up" the baseline.

## 2. Evasion cost taxonomy

Each candidate evasion is scored on three costs:

### Capability cost

Additional capability the attacker must possess. Levels:

- **None**: the base attack already includes this capability.
- **Modest**: requires programming (scripts, curl-level HTTP crafting) but no exotic capability.
- **Significant**: requires infrastructure (long-running C2, distributed identities) or paid services (residential proxies).
- **Extreme**: requires nation-state-level resource (e.g., certificate injection, side-channel).

### Operational cost

How much the evasion slows or complicates the attack.

- **None**: no slowdown.
- **Low**: seconds to minutes added.
- **Medium**: hours added, or attack requires multi-session execution.
- **High**: attack becomes infeasible or unrecognisable as the same attack class.

### Detection-elsewhere cost

Whether the evasion introduces a new signal that a different detection would catch. Positive value for defenders.

- **None**: evasion is silent everywhere.
- **Low**: introduces subtle side-effect (e.g., unusual user-agent).
- **Medium**: introduces a distinct new event (e.g., additional IAM call to warm up baseline).
- **High**: fundamentally reshapes attack surface in a way monitored by unrelated tools (e.g., forces use of a paid proxy service with its own detection).

An evasion is worth pursuing (from the attacker's perspective) only if all three costs are low. From the defender's perspective, the primitive is robust if attackers face medium-plus on any axis.

## 3. Per-primitive evasion template

Each primitive's `adversarial_evasion.md` follows this structure:

```markdown
# Primitive NN — Adversarial Evasion Analysis

## Baseline signature

[What CloudTrail conditions the primitive fires on. Copy from the
 primitive's cloudtrail_lake_query.sql structure.]

## Evasion candidates

### Evasion 1: [name]

[Description: what the attacker does instead of the baseline attack]

- **Capability cost**: [None/Modest/Significant/Extreme] — [why]
- **Operational cost**: [None/Low/Medium/High] — [why]
- **Detection-elsewhere cost**: [None/Low/Medium/High] — [why]
- **Blind attacker likelihood**: [Never/Unlikely/Possible/Likely]
- **Graybox attacker likelihood**: [as above]
- **Whitebox attacker likelihood**: [as above]

[2-4 sentences on residual detection: what still catches the evaded attack.]

### Evasion 2: [name]
...
```

Each primitive produces 2–4 evasion candidates. The mix should include at least one blind-attacker-plausible evasion (i.e., a naive attacker might stumble into it) and at least one whitebox-optimised evasion.

## 4. Consolidated table

`evaluation_report.md` includes an aggregate evasion table:

| Primitive | Evasion | Cap cost | Op cost | Det-elsewhere cost | Whitebox likelihood |
|---|---|---|---|---|---|
| 01 — IMDS extraction | Pre-fetch credentials, use off-box | None | Low | Low | Possible |
| 01 | ... | ... | ... | ... | ... |
| 02 | ... | ... | ... | ... | ... |
...

This table lets the report state summary claims like "of PathTriage's 5 primitives, 3 have no low-cost whitebox evasion" — a quantitative structural claim about the module's evasion robustness.

## 5. Consolidated evasion — thesis integration

The aggregate table feeds thesis §5 (Discussion) with material for two claims:

1. **PathTriage's baseline-aware joins raise evasion cost**. Sigma-style stateless rules can be evaded by any variation in event conditions; primitive queries that require historical baseline anchoring force evaders to warm up the baseline (medium capability + medium operational cost).
2. **Some primitives have irreducible weak spots**. Where the evasion analysis identifies a low-cost whitebox evasion, the primitive is honest about it — the report does not overclaim.

Being honest about the weak spots is a report-quality signal that PathTriage does not overclaim.
