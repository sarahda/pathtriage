# Primitive 05 — Trust Topology

## Coverage

This primitive covers one verified AWS attack path:

| Path | Attack | Trust exploitation |
|---|---|---|
| P4 | AssumeRole Chain | User assumes R1; R1's trust relationship allows R1 to assume R2 (which holds admin); user pivots through R1 to R2 |

The primitive detects **multi-hop `sts:AssumeRole` chains** originating from a single starting principal within a short time window. Single-hop `AssumeRole` events are legitimate (CI/CD, cross-account access, MFA-token flows), so the signal is the *chain length* and *chain novelty*, not any individual hop.

## Detection Rationale

`sts:AssumeRole` is a normal AWS operation. CI/CD pipelines routinely assume 1-2 roles per operation; cross-account users assume role in target account; MFA flows include a `GetSessionToken` step that surfaces similarly. A primitive that fires on any AssumeRole is unusable.

The attack signature is a **structural anomaly in trust chain traversal**:

1. **Chain length**: normal operations complete at 1-2 hops. Attack chains extend to 3+ hops as the attacker seeks the destination admin role through intermediate trust hops.
2. **Chain novelty**: legitimate multi-hop chains are stable — CI/CD's `user → CIRole → DeployRole` sequence repeats identically for months. Attack chains explore new sequences the starting principal has never traversed.
3. **Chain termination**: the terminal role in the chain typically holds elevated privileges (admin, IAM, resource creation). Chains ending at low-privilege roles are uninteresting.

The baseline-join dimension is **starting-principal-chain-history**. For each `AssumeRole` sequence starting from principal P within N minutes:

- **Expected**: P has traversed this exact sequence (P → R1 → R2 → ...) many times in the last 90 days.
- **Anomalous**: P has traversed part of this sequence but not the full extension, or the terminal role is new for P.

## Baseline-Join Approach

Query self-joins CloudTrail events to reconstruct AssumeRole chains, then joins each chain against three baselines:

1. **Full-chain history**: has principal P traversed the sequence (R1 → R2 → ... → Rn) before? Established chains are legitimate CI/CD or ops patterns.
2. **Terminal-role history**: has principal P ever reached role Rn before, via any chain? A first-time terminal role for P is a strong signal.
3. **Terminal-role privilege scope**: does Rn hold admin-equivalent policies? Elevation-terminal chains are the highest-confidence attack signal.

The primitive fires on 3+ hop chains where the terminal role is new for the starting principal AND admin-equivalent. Confidence tiered based on chain length and terminal privilege.

## Query Semantics

See `cloudtrail_lake_query.sql`. In prose:

```
For each principal P in the last 24h:
    Reconstruct AssumeRole chains within a :chain_window_min window
    Each chain is a sequence of AssumeRole events where:
        chain[0].caller = P
        chain[i+1].caller = chain[i].assumed_role
        all events within :chain_window_min minutes

For each chain of length ≥ 3:
    If P has never traversed this chain before → chain_novel
    If P has never reached the terminal role → terminal_novel  
    If terminal role holds admin policies → admin_terminal
    
    Fire if (terminal_novel OR admin_terminal)
```

## Coverage per Path

See `paths.md`. Summary:

- **P4**: attacker (user) assumes R1, R1 assumes R2 (admin). 2-hop chain from user's perspective (technically 3 identities: user, R1, R2). Terminal role R2 is new for the user and admin-equivalent. Fire reason: `admin_terminal_novel_chain`. Confidence: **high**.

## Preventive Control

`scp_snippet.json` restricts `sts:AssumeRole` chain depth via role trust policy patterns and enforces MFA on any role that can be assumed by another role (transitive trust guard).

- **Chain-depth SCP**: denies `sts:AssumeRole` when the caller is already an assumed-role session AND the target role does not have an explicit "chain-source-allowed" tag. This structurally limits transitive trust.
- **Terminal-role MFA gate**: denies `sts:AssumeRole` to admin-tagged roles unless MFA condition present in the caller's session context. Legitimate admin access requires MFA; role-to-role chained access does not carry MFA (session context propagation is limited).

Both preventions have known limitations:

- Chain-depth SCP requires organisation-wide tag discipline; deployment complexity is significant.
- Terminal-role MFA gate blocks legitimate service-to-service chains (CI/CD → admin role for automation). Requires per-role exemptions or a distinct authorization mechanism (e.g., session tag-based).

The detection primitive is essential — SCPs alone cannot express "novel chain" without runtime state.

## Evaluation Summary

Populated after Phase 4 execution. See `evaluation.md`.

## References

- Adversarial evasion: `adversarial_evasion.md`
- AWS↔Azure signal correspondence: `azure_symmetry.md`
- Per-path detection signature: `paths.md`
- Related-work coverage: `../../methodology/related_work.md` §3
