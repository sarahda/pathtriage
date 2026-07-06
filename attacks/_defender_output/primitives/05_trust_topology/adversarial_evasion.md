# Primitive 05 — Trust Topology — Adversarial Evasion

## Baseline signature

Fires on multi-hop `sts:AssumeRole` chains (≥ `:min_chain_length` hops) originating from a single starting principal within `:chain_window_min` minutes, where at least one of: chain signature is novel for the principal, terminal role is novel for the principal, terminal role is admin-equivalent. Confidence tiered by combination.

## Evasion candidates

### Evasion 1 — Split the chain across a longer time window

**Description**: attacker executes hop 1 at time T, then hop 2 at time T+16 min. Chain reconstruction fails because `:chain_window_min = 15` limits joins to 15-minute intervals. Primitive sees two independent single-hop AssumeRole events, neither triggering the chain-length threshold.

- **Capability cost**: None.
- **Operational cost**: Low — 16 minutes idle time between hops.
- **Detection-elsewhere cost**: None.
- **Blind attacker likelihood**: Never — attackers execute chains at attack speed.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: primitive 05 misses this. Mitigation: extend `:chain_window_min` to 4 hours (240). Cost: significantly more legitimate chains include across-workday breaks that would be incorrectly reconstructed as chains. Trade-off in `evaluation.md`.

Alternative: track long-lived assumed-role sessions and fire on any role transition regardless of time gap. This is a distinct primitive concept (session-tracking primitive) not implemented.

### Evasion 2 — Use only pre-established chains

**Description**: attacker has compromised principal P and observes that P routinely uses chain `P → R1 → R2 → R3`. Attacker uses P's own established chain and reaches R3. The chain signature is not novel (P has traversed it before) and terminal is not novel (P has been at R3 before). Primitive does not fire.

- **Capability cost**: Modest — attacker must first compromise a principal that already has admin-terminating chains.
- **Operational cost**: None.
- **Detection-elsewhere cost**: None.
- **Blind attacker likelihood**: Unlikely — attackers exploit whatever chains are reachable, not just familiar ones.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: primitive 05 misses this. Fundamental limitation — the primitive is anomaly-based, and an attacker perfectly mimicking established behavior evades anomaly detection. Mitigation is out-of-scope: post-hoc investigation of any admin access reveals the compromised source principal via cross-referencing with other signals (unusual login times, source IP anomalies at the initial principal-compromise step).

Alternative: cap admin session duration (see `scp_snippet.json` statement 3). Even if primitive 05 misses the assumption, the short session cap limits attacker action time.

### Evasion 3 — Insert a benign intermediate hop to break signature match

**Description**: attacker's real target chain is `P → R1 → R2 → R3` (admin). Attacker performs `P → R1 → R_bystander → R2 → R3`, inserting a benign role R_bystander. Chain signature includes R_bystander, which changes the signature. If the modified signature has been seen before, primitive treats as legitimate.

- **Capability cost**: Modest — attacker needs `sts:AssumeRole` permissions from R1 for R_bystander and from R_bystander for R2.
- **Operational cost**: Low.
- **Detection-elsewhere cost**: Low.
- **Blind attacker likelihood**: Never.
- **Graybox attacker likelihood**: Unlikely.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: `terminal_novel` and `admin_terminal` still fire on the R3 terminus. Only if the attacker's inserted hop makes the terminal not-novel does this evasion work — and that requires the modified chain to have been traversed before, which is rare. Practically, primitive 05 still catches this.

### Evasion 4 — Assume role from an initial identity that already has admin history

**Description**: attacker compromises a principal (e.g., a legitimate ops user) whose historical chain patterns include reaching admin terminals. Attacker then reaches admin via the same familiar path. `terminal_novel = FALSE` because the terminal is known; primitive does not fire on `admin_terminal_novel_chain`.

- **Capability cost**: Significant — attacker must compromise a principal with pre-existing admin access history.
- **Operational cost**: None.
- **Detection-elsewhere cost**: Medium — compromising an admin-adjacent principal is itself a high-value target that other detections cover (e.g., primitive 04 credential theft, MFA challenges on suspicious logins).
- **Blind attacker likelihood**: Never.
- **Graybox attacker likelihood**: Unlikely.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: primitive 05 misses this by design (anomaly-based detection cannot fire on non-anomalous behavior). Coverage relies on adjacent primitives (04 for credential theft, and separate primitives for authentication anomalies).

### Evasion 5 — Use a non-AssumeRole session mechanism

**Description**: attacker uses `sts:GetSessionToken` or `sts:GetFederationToken` to obtain temporary credentials, rather than `sts:AssumeRole`. Primitive 05's `assume_role_events` CTE filters on `AssumeRole` only, missing the other STS session APIs.

- **Capability cost**: Modest — the alternative APIs have different permission requirements (e.g., `GetSessionToken` requires the caller's own long-term keys, not always available to attackers).
- **Operational cost**: Low.
- **Detection-elsewhere cost**: Medium — the alternative session APIs are unusual and often flagged by GuardDuty or other tools.
- **Blind attacker likelihood**: Unlikely.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: primitive 05 misses this. Extension to include all STS session-creation APIs (`AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`, `GetSessionToken`, `GetFederationToken`) closes this gap. Trivial extension; deferred to Phase 4 if measured need.

## Summary — Whitebox Evasion Landscape

| Evasion | Reachable | Cost bar |
|---|---|---|
| 1. Split chain across time window | ✓ | Very low |
| 2. Use only pre-established chains | ✓ (requires precondition) | Compromise precondition |
| 3. Insert benign intermediate hop | ✗ (terminal still fires) | — |
| 4. Assume from admin-history principal | ✓ (requires precondition) | High capability |
| 5. Use non-AssumeRole STS API | ✓ | Modest capability |

**Primitive 05 has three reachable whitebox evasions** (1, 2, 5). Evasions 2 and 4 require preconditions (compromise of specific principal types) that limit their applicability. Evasion 1 is the most impactful — a simple time-based evasion defeats the primitive's chain reconstruction.

Mitigations:

- Evasion 1: extend chain window at cost of precision (tunable parameter)
- Evasion 2/4: complementary detection (session-tracking, authentication anomaly)
- Evasion 5: extend query to include other STS session APIs (Phase 4 extension)

For blind and graybox attackers, primitive 05 catches the naive multi-hop attack patterns that constitute the majority of trust-topology exploitation attempts. Sophisticated attackers with awareness of chain detection can evade via evasions 1 or 2.

## Structural observation

Primitive 05 is the most **anomaly-dependent** primitive in the module. Primitives 01-04 have signature components that fire on definite attack indicators (self-attach, admin-content, credential-file-name, novel-key-ID) independent of baseline. Primitive 05 has no such signature component — chains are legitimate operations, and only the anomaly signal (novelty) distinguishes attack.

This makes primitive 05 more sensitive to baseline pollution (a well-crafted attack that establishes false baseline will evade forever) and more useful in high-baseline-quality environments (where any anomaly is significant). Deployment recommendation in `README.md` §Detection Rationale.

## Comparison to primitives 01-04 evasion landscapes

- Primitive 01: 1 low-cost whitebox evasion (SSH tunnel from instance)
- Primitive 02: 1 low-cost whitebox evasion (custom-named admin policy)
- Primitive 03: 3 low-cost whitebox evasions (multi-step, correlation window, encoded wildcards)
- Primitive 04: 3 low-cost whitebox evasions (delay, IP/UA divergence, non-standard file names)
- Primitive 05: 3 low-cost whitebox evasions (time-split, established chains, non-AssumeRole STS)

Total across module: 11 documented low-cost whitebox evasions. This is the module's honest disclosure of coverage limitations. The report's Discussion section (thesis §5) uses this catalogue to argue that **defence in depth is essential** — no single primitive is evasion-proof, but the union across primitives is much more resilient than any individual primitive.
