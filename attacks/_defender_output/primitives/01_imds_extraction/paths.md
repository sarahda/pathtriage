# Primitive 01 — Per-Path Signature Details

## P1 — PassRole + RunInstances

**Attack summary**: attacker with `iam:PassRole` + `ec2:RunInstances` launches a new EC2 with an admin instance profile, then obtains credentials from that instance's IMDS.

**Signature on this primitive**:

- Attacker launches instance `i-A` with role `AdminRole`.
- The `RunInstances` event itself is not fired by this primitive (that's IAM/EC2 misconfiguration territory — covered by CIS controls).
- The subsequent use of `AdminRole` credentials from `i-A`'s session is fired **if** the attacker uses those credentials from any location.
- **IP anomaly**: fires because `i-A` has no egress baseline (freshly launched; `instance_egress_baseline` returns NULL). Baseline-empty is treated as anomaly per query Step 4.
- **UA anomaly**: does not fire (session is unestablished, so UA baseline does not apply).

**Detection reason emitted**: `ip` (baseline empty).

**MTTD expectation**: seconds — the attacker's first API call using the stolen credentials fires.

**Comparison-tool coverage**:

- Cloudsplaining: **partial** — flags overly-broad `iam:PassRole` in the attacker's own policy, but does not observe the attack.
- Prowler: **partial** — audit rule flags instances launched with sensitive roles, but not runtime use.
- Datadog CloudSIEM: **detect** — rule `AWS EC2 Instance Started With Highly Privileged Instance Profile` fires. However, does not correlate with subsequent credential use.
- Sigma HQ: **miss** — no rule for this pattern in the cloud category as of July 2026.
- CIS AWS Foundations v3.0: **partial** — Control 1.19 (Ensure IAM instance roles are used) is preventive against a different subclass; does not prevent P1.

## P2 — IMDS SSRF Credential Theft

**Attack summary**: attacker exploits SSRF in a web application on an EC2 instance to make the application read its own IMDS endpoint and return credentials in the HTTP response. Attacker receives credentials off-box.

**Signature on this primitive**:

- The credential extraction itself is not visible in CloudTrail (IMDS is EC2-local, not logged to CTL).
- The subsequent use of the extracted credentials from the attacker's own environment is fired.
- **IP anomaly**: fires — attacker's source IP is not in the compromised app's VPC egress set.
- **UA anomaly**: often fires — attackers typically use curl/Python default UAs, not the app's SDK UA.

**Detection reason emitted**: `ip+ua` in the common case, `ip` if the attacker spoofs the SDK UA.

**MTTD expectation**: seconds — attackers use fresh credentials immediately.

**Comparison-tool coverage**:

- Cloudsplaining: **miss** — SSRF is application-level, not policy-level.
- Prowler: **partial** — flags IMDSv1 enabled instances (a preventive check) but does not detect use.
- Datadog CloudSIEM: **detect** — rule `AWS Access Denied From Unexpected Location` fires post-detection on high-value APIs, but often after the attacker completes reconnaissance.
- Sigma HQ: **detect** — rule `aws_ec2_metadata_service_credential_theft` matches. Coverage is on the metadata access pattern from the app; may miss the subsequent use.
- CIS AWS Foundations v3.0: **detect** — Control 5.4 (Ensure IMDSv2 is enabled) is preventive. Fully mitigated by the SCP in `scp_snippet.json`.

## P6 — EC2 Instance Profile Abuse

**Attack summary**: attacker with prior access (SSH, RCE) to an EC2 instance reads IMDS credentials, exfiltrates them off-box, and uses them from the attacker's own machine or another AWS account.

**Signature on this primitive**:

- **IP anomaly**: fires — attacker's source IP is not in the instance's egress set.
- **UA anomaly**: fires if session is established — attackers rarely spoof the exact SDK UA seen for that instance. For fresh instances (attacker compromised the instance shortly after launch), UA anomaly may not fire.

**Detection reason emitted**: `ip+ua` in most cases; `ip` alone for compromised-fresh-instance scenarios.

**MTTD expectation**: seconds — same as P1/P2.

**Comparison-tool coverage**:

- Cloudsplaining: **miss** — no policy-level indicator for this attack.
- Prowler: **miss** — audit tool, does not observe.
- Datadog CloudSIEM: **partial** — rules for unusual API sources exist but require baseline-anomaly correlation Datadog does not offer natively at rule-level.
- Sigma HQ: **partial** — some off-instance credential-use rules exist but rely on stateless UA/IP list checks, not per-session baselines.
- CIS AWS Foundations v3.0: **miss** — no relevant control (CIS presumes IMDS access is legitimate).

## Coverage Matrix Row

For inclusion in `methodology/related_work.md` §3:

| Path | Cloudsplaining | Prowler | Datadog | Sigma | CIS | PathTriage primitive |
|---|---|---|---|---|---|---|
| P1 | partial | partial | detect | miss | partial | **01** |
| P2 | miss | partial | detect | detect | detect | **01** |
| P6 | miss | miss | partial | partial | miss | **01** |

Structural gap: **P6 is missed by 3 of 5 comparison tools**. Datadog and Sigma have partial coverage that requires baseline-anomaly logic those tools do not natively express. PathTriage Primitive 01 covers P6 fully via the session-UA baseline. This is one of the "at least one path missed by all commercial baselines" contributions cited in `evaluation_protocol.md` §6.
