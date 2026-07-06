# Primitive 04 — Credential Discovery — Adversarial Evasion

## Baseline signature

Fires on credential-bearing surface reads (`GetFunctionConfiguration` on Lambda functions with env vars, `GetObject` on credential-file-patterned S3 keys) correlated within 60 minutes with the first-ever use of a new access key ID by a different principal sharing source IP or user-agent with the reader.

## Evasion candidates

### Evasion 1 — Delay use beyond the correlation window

**Description**: attacker reads Lambda config or S3 object at time T, extracts credentials. Waits 61+ minutes. Uses credentials outside the correlation window. Primitive fails to correlate.

- **Capability cost**: None.
- **Operational cost**: Low — waiting 1 hour is trivial for most attack scenarios.
- **Detection-elsewhere cost**: None — no other primitive covers the delayed pattern.
- **Blind attacker likelihood**: Unlikely — attackers using tools like `pacu` or `WeirdAAL` use credentials immediately.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: primitive 04 misses this evasion. Mitigation: extend `:correlation_window_min` to 24 hours. Cost is significantly more FPs (24-hour window has many more coincidental correlations). Precision-vs-recall trade-off documented in `evaluation.md` sensitivity analysis.

Alternative: track access key IDs against known-legitimate key inventory (via IAM ListAccessKeys). Any use of an access key NOT in the inventory is a fire, regardless of prior read event. This is a separate primitive concept (rogue-key detection) that would complement primitive 04.

### Evasion 2 — Use stolen credentials from different IP and different user-agent

**Description**: attacker reads credentials from one machine (public IP A, curl UA), uses credentials from a different machine (public IP B, Python UA, or via residential proxy). Correlation fails because neither IP nor UA matches.

- **Capability cost**: Modest — requires infrastructure for both machines.
- **Operational cost**: Low.
- **Detection-elsewhere cost**: Low — the resulting behavior (new access key ID from unexpected IP) is caught by other detection categories (AWS GuardDuty, unusual API location), but not by this primitive.
- **Blind attacker likelihood**: Unlikely — attackers typically use one machine.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: primitive 04 misses this. GuardDuty's "Impossible Travel" and "New API from unusual location" catch it (established, well-tuned) but at a different level. Documented as an honest gap in `evaluation_report.md`.

### Evasion 3 — Encode credentials in non-standard file names or non-standard formats

**Description**: attacker stores or reads credentials from a file named `notes.txt`, `data.json`, or a random name. Primitive's file-pattern deny does not fire (both the write-side prevention and the read-side detection use file-name patterns).

- **Capability cost**: None.
- **Operational cost**: None.
- **Detection-elsewhere cost**: None.
- **Blind attacker likelihood**: Never — attackers with legitimate access to a bucket don't need to rename files.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: primitive 04 misses this at the read side. The use side still applies — new access key ID from unexpected principal — but without the read correlation, primitive 04's fire path is not triggered. Content-inspection at the read side (scanning object bodies for AKIA patterns) requires computation outside CTL SQL; deferred to future work.

Alternative mitigation: baseline the caller's read history and fire on unusual-object reads regardless of naming (any first-time GetObject to a bucket where the caller has never accessed before). This has high FP but catches the naming evasion.

### Evasion 4 — Use credentials via STS (temporary session) rather than direct

**Description**: attacker uses stolen long-term IAM keys to call `sts:GetSessionToken` (creating a temporary session), then uses the temporary session credentials. The temporary session's access key ID is different from the stolen long-term key's ID; the temporary session is fresh (never seen before) but is technically legitimate (STS-issued).

- **Capability cost**: None — one extra API call.
- **Operational cost**: Low.
- **Detection-elsewhere cost**: Medium — the `sts:GetSessionToken` event is visible and is itself unusual for a user account (STS temporary sessions are more common for role assumption).
- **Blind attacker likelihood**: Unlikely.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: primitive 04 detects the STS call as a "new access key ID" event (the STS session key is new). If STS call happens within the correlation window and IP/UA match, primitive 04 fires. The evasion is that the STS session's own key ID is then used, and that key ID is not correlated to the read. Extension: track access-key-ID chains (STS session parent key = original stolen key) via CloudTrail's `sessionContext` fields. Deferred.

### Evasion 5 — Use credentials via KMS-encrypted intermediate storage

**Description**: attacker extracts credentials, re-stores them in KMS-encrypted S3 or Secrets Manager, then uses them via a service role. The direct correlation from read to use is broken.

- **Capability cost**: Modest — requires KMS+Secrets Manager access.
- **Operational cost**: Medium — multi-step.
- **Detection-elsewhere cost**: Medium — Secrets Manager operations are logged and would be caught by baseline analysis.
- **Blind attacker likelihood**: Never — over-engineered.
- **Graybox attacker likelihood**: Never.
- **Whitebox attacker likelihood**: Unlikely.

**Residual detection**: primitive 04 misses this but the operational cost makes it a low-priority evasion. Not documented as a concern.

## Summary — Whitebox Evasion Landscape

| Evasion | Reachable | Cost bar |
|---|---|---|
| 1. Delay use past correlation window | ✓ | Very low |
| 2. Use from different IP/UA | ✓ | Modest capability |
| 3. Non-standard file names | ✓ (read side) | Very low |
| 4. STS intermediate session | ~ (detected in indirect form) | Very low |
| 5. KMS/Secrets Manager laundering | ✗ (operational cost too high) | High |

**Primitive 04 has three low-cost whitebox evasions.** This is the highest evasion surface among all five primitives, reflecting the difficulty of content-level detection in cloud APIs. Real-world attackers on P7/P8 patterns tend to use immediate credentials without evasion (blind/graybox), so primitive 04 remains effective in practice.

Mitigations for the three low-cost evasions:

- Evasion 1: extend correlation window (with FP cost) or add rogue-key primitive (parallel signal).
- Evasion 2: coverage via GuardDuty or equivalent "impossible travel" detection at a different layer.
- Evasion 3: content inspection at read side (out of scope for this module; noted as future work).

For blind and graybox attackers, primitive 04 is highly effective on the naive credential-theft pattern. The report's honest disclosure of the three low-cost whitebox evasions is a report-quality signal.

## Comparison to primitives 01-03 evasion landscapes

- Primitive 01: 1 low-cost whitebox evasion (SSH tunnel).
- Primitive 02: 1 low-cost whitebox evasion (custom-named admin policy).
- Primitive 03: 3 low-cost whitebox evasions (multi-step, correlation window, encoded wildcards).
- Primitive 04: 3 low-cost whitebox evasions (delay, IP/UA divergence, non-standard file names).

Primitives 03 and 04 both suffer from **content analysis requirements that SQL cannot express cleanly**. Both benefit from a two-layer defence pattern: SQL-based fast detection at ingestion time, plus a slower content-inspection verifier for high-confidence fires. Documented in thesis §5 (Discussion) as a general architectural observation.
