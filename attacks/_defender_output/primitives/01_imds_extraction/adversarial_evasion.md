# Primitive 01 — IMDS Extraction — Adversarial Evasion

## Baseline signature

Fires on CloudTrail events where an EC2-instance-role temporary credential (`AssumedRole` with session name `i-<id>`) is used from a source IP not in the instance's expected egress set, OR from a user-agent not seen in the last 30 days for an established role-session.

## Evasion candidates

### Evasion 1 — Egress via the instance itself (SSH tunnel / SOCKS proxy)

**Description**: attacker with shell access to the compromised instance (P6) routes their AWS SDK traffic through the instance rather than using the credentials directly from their own laptop. The AWS API calls then originate from the instance's own egress IP, matching the baseline.

- **Capability cost**: None — SSH+SOCKS is trivial once you have shell.
- **Operational cost**: Low — slight added latency (~1 RTT) per API call.
- **Detection-elsewhere cost**: Medium — the SSH session or the outbound proxy connection is itself a signal at the network layer; VPC Flow Logs or EDR can catch prolonged SSH sessions with unusual data patterns. Not detected by primitive 01, but detected by adjacent controls.
- **Blind attacker likelihood**: Unlikely — a blind attacker takes the credentials off-box because that's what tutorials show.
- **Graybox attacker likelihood**: Possible — an attacker who knows "source IP is monitored" may reach this evasion.
- **Whitebox attacker likelihood**: Likely — this is the first evasion a whitebox attacker considers.

**Residual detection**: primitive 01 misses this evasion. VPC Flow Logs anomaly (persistent SSH tunnel egressing to unusual IPs) catches it; that's a separate primitive class (network-level, out of scope for the current AWS CloudTrail-focused module). This is documented in `evaluation_report.md` as an honest weakness.

### Evasion 2 — User-agent spoofing to match SDK-typical UA

**Description**: attacker sets the AWS SDK user-agent to a value seen in the legitimate baseline (e.g., `aws-cli/2.15.0 Python/3.11.5 Linux/6.5.0`). Defeats UA-anomaly alone.

- **Capability cost**: None — SDK UA is settable via `User-Agent` header override or SDK config.
- **Operational cost**: None.
- **Detection-elsewhere cost**: None.
- **Blind attacker likelihood**: Unlikely — few off-the-shelf credential-abuse tools spoof UA.
- **Graybox attacker likelihood**: Possible.
- **Whitebox attacker likelihood**: Likely.

**Residual detection**: IP anomaly still fires unless combined with Evasion 1. UA spoofing alone does not defeat primitive 01 because the IP anomaly path is independent of UA.

### Evasion 3 — Baseline warm-up before attack

**Description**: attacker executes benign-looking API calls from their off-box IP prior to the credential-abuse attack, using the same UA they intend to use for the attack. This warms up the session's UA baseline so their attack-time UA is no longer "unseen."

- **Capability cost**: Modest — requires the attacker to have credentials for enough time to establish a baseline (30-day window means 5+ calls over multiple days).
- **Operational cost**: High — 30-day timeline is incompatible with most active attack scenarios (attackers typically operate on hour-to-day time scales).
- **Detection-elsewhere cost**: Medium — the warm-up calls themselves produce baseline-anomaly (source IP is new for the session), and are logged. A backward-looking forensic analysis catches the pattern.
- **Blind attacker likelihood**: Never — no blind attacker plans a 30-day baseline warm-up.
- **Graybox attacker likelihood**: Unlikely — the operational cost is prohibitive for most attack scenarios.
- **Whitebox attacker likelihood**: Possible — for high-value long-lived access, a whitebox attacker might invest.

**Residual detection**: the warm-up phase itself is IP-anomaly and fires the primitive. Only successful evasion is if the attacker's warm-up escapes detection at the time (e.g., defender alert fatigue). Long-term persistence attacks may achieve this; short-window attacks (the common case) cannot.

### Evasion 4 — Session-context stripping (session-token replay from off-box, minus session name)

**Description**: attacker exfiltrates the STS temporary access key and secret without also exfiltrating (or without using) the session context. Uses only the raw access key ID + secret. CloudTrail records `userIdentity.type` differently (no `sessionContext.sessionIssuer`).

- **Capability cost**: Modest — requires manipulating the AWS SDK to bypass session-context reporting; not all SDKs allow this.
- **Operational cost**: Low.
- **Detection-elsewhere cost**: Medium — the resulting `userIdentity.type` is unusual (temporary credentials without session issuer), which is itself a signal that a distinct primitive could catch.
- **Blind attacker likelihood**: Never.
- **Graybox attacker likelihood**: Unlikely.
- **Whitebox attacker likelihood**: Possible.

**Residual detection**: primitive 01's `candidate_events` CTE filters on session name regex, so this evasion falls outside primitive 01's fire condition. However, it produces a distinct CloudTrail pattern that is itself detectable — future primitive extension.

## Summary — Whitebox Evasion Landscape

For a whitebox attacker (full repository read):

| Evasion | Reachable | Cost bar |
|---|---|---|
| 1. SSH tunnel from instance | ✓ | Very low |
| 2. UA spoof alone | ✗ (IP still fires) | — |
| 3. Baseline warm-up | ~ (only for long-lived attacks) | Very high operational cost |
| 4. Session-context strip | ~ (SDK-dependent) | Modest capability |

**Primitive 01 has one low-cost whitebox evasion (Evasion 1)**. This is honestly reported. The mitigation is a companion network-layer primitive that catches the SSH-tunnel behaviour; that primitive is out of scope for the current module but is noted as future work in `evaluation_report.md`.

For blind and graybox attackers — the majority of real-world adversaries — the primitive is highly effective. The evasion landscape is a whitebox-specific weakness, not a general one.
