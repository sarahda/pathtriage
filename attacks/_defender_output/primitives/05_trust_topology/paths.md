# Primitive 05 — Per-Path Signature Details

## P4 — AssumeRole Chain

**Attack summary**: attacker has an IAM user with `sts:AssumeRole` permission for role R1. R1's trust policy allows it to be assumed by the user; R1 in turn has `sts:AssumeRole` on role R2, which holds `AdministratorAccess`. The attacker calls `AssumeRole R1` → then from R1's session, calls `AssumeRole R2` → operates as R2 with admin privileges. The user was never granted direct access to R2 but reaches admin via the transitive trust.

**Signature on this primitive**:

- Hop 1: user calls `AssumeRole` with target = R1. Event 1.
- Hop 2 (within 15 min): assumed R1 session calls `AssumeRole` with target = R2. Event 2.
- Chain length: 2 hops from user's perspective (or 3 identities: user, R1, R2). Primitive uses 3+ hop threshold in default config, so P4 exactly at the threshold — depends on how "chain" is defined. Adjustable via `:min_chain_length`.
- Terminal role R2 is new for the user (`terminal_novel` = TRUE).
- R2 holds `AdministratorAccess` (`admin_terminal` = TRUE).
- Chain signature `arn:R1|arn:R2||` never seen for this user before (`chain_novel` = TRUE).
- Fire reason: `admin_terminal_novel_chain`.
- Confidence: **high**.

**Baseline join contribution**: essential. Legitimate CI/CD chains (`user → CIRole → DeployRole`) have long histories; the chain signature match filters them out. Attack chains explore new terminal roles; the terminal_novel check catches them even if some intermediate hops are familiar.

**MTTD expectation**: 1-15 minutes. Fire occurs on the last hop event (when the terminal admin role is reached), so MTTD is bounded by the chain window duration. For a 2-hop attack executed at attack speed (<1 min), MTTD ≈ seconds.

**Chain length threshold**: default `:min_chain_length = 3` is optimised for 3-identity chains (user → R1 → R2, which shows as chain_length = 2 in the query's counting). Setting `:min_chain_length = 2` catches P4 explicitly; setting to 3 requires an extra hop that P4 does not have by default. Tuning documented in evaluation.

**Comparison-tool coverage**:

- **Cloudsplaining**: **partial** — flags policies that grant `sts:AssumeRole` on wildcard resources. Catches the trust misconfiguration at policy-review time.
- **Prowler**: **partial** — check `iam_role_chained_iam_full_access` (recent addition) flags role trust chains ending at IAM-admin roles. Static analysis, not runtime.
- **Datadog CloudSIEM**: **partial** — rule `AWS Multiple Role Assumptions in Short Time` fires on chained assumes but does not distinguish novel from legitimate chains, generating high FP.
- **Sigma HQ cloud**: **miss** — no rule specifically for chain traversal patterns.
- **CIS AWS Foundations v3.0**: **miss** — no preventive control for chain depth.

## Coverage Matrix Row

For inclusion in `methodology/related_work.md` §3:

| Path | Cloudsplaining | Prowler | Datadog | Sigma | CIS | PathTriage primitive |
|---|---|---|---|---|---|---|
| P4 | partial | partial | partial | miss | miss | **05** |

Structural gap: **3 tools have partial coverage but none combines chain reconstruction with novelty baseline**. Datadog's "multiple assumptions" rule fires on legitimate ops (any CI/CD deploy triggers it); Prowler's chain analysis is static; Cloudsplaining is policy-static. Primitive 05's contribution is the **novelty-baseline filter** — legitimate long-standing chains do not fire because their signatures are established.

## Cross-primitive context — chain detection vs credential detection

Primitive 04 detects credential theft (attacker acquires new credentials). Primitive 05 detects trust exploitation (attacker uses existing trust chains to reach new privilege). Both involve "attacker reaches privilege they didn't have before," but the mechanisms differ:

- Primitive 04: theft of static credentials, off-band use of same principal
- Primitive 05: legitimate use of trust chains to traverse principals

The distinction matters for defensive response:

- Primitive 04 fire: rotate/revoke leaked credentials, investigate storage surface
- Primitive 05 fire: revoke role trust relationships, investigate transitive trust design

Real-world attacks often combine both — attacker steals credentials for user P (primitive 04), then uses P to traverse a trust chain (primitive 05). Both fires can appear from the same attack, which is expected and desired behaviour.

## Azure equivalent — Z7

Z7 (Managed Identity / SP Chain) is the direct Azure analogue — MI assigns role to a second identity, or one MI impersonates another. Not yet verified (W7-W8 planned). See `azure_symmetry.md` for signal correspondence.
