# Primitive 01 — IMDS Extraction

## Coverage

This primitive covers three verified AWS attack paths:

| Path | Attack | Role of IMDS |
|---|---|---|
| P1 | PassRole + RunInstances | Attacker launches an EC2 with a passable admin role; the attacker (or attacker's code on the instance) then reads role credentials from IMDS on the newly-launched instance |
| P2 | IMDS SSRF Credential Theft | Attacker exploits an SSRF vulnerability in a web application to make the application read its own IMDS endpoint and return credentials |
| P6 | EC2 Instance Profile Abuse | Attacker with prior access to an EC2 instance reads IMDS credentials and reuses them from off-box (attacker's laptop, another AWS account, etc.) |

All three paths converge on the same defender-observable signature: **AWS API calls made using IMDS-issued temporary credentials from an unexpected source location**. The primitive detects this convergence, not the three paths independently.

## Detection Rationale

An EC2 instance role's temporary credentials are legitimately used by code running on the issuing instance. Their appearance in CloudTrail is normal — every application-level AWS SDK call from a role-bearing instance emits an event with `userIdentity.type = "AssumedRole"` and a session name of the form `i-<instance-id>`.

The attack signature is a **spatial mismatch**: the same credentials appear in CloudTrail events from an IP address or user-agent inconsistent with the instance's location. Legitimate use is confined to the instance's own network path; attack use appears from elsewhere.

The baseline-join dimension is therefore **caller-instance-source binding**. For every event using an EC2 instance role's temporary credentials:

- **Expected**: the source IP belongs to the instance's own VPC egress path (NAT gateway, direct route), or the instance's public IP if directly-attached. The user-agent conforms to a small set (AWS SDK, boto3, aws-cli).
- **Anomalous**: source IP does not match the instance's egress; or user-agent is external (browsers, curl, Postman-like tools).

The primitive fires on events where the mismatch is present within a bounded lookback window (24h default, tunable).

## Baseline-Join Approach

The query joins each candidate event against two historical anchors:

1. **Instance metadata**: what is the instance's expected egress IP set? Derived from `DescribeInstances` output at instance-launch time; refreshed daily.
2. **Role-session history**: what user-agents has this role-session (`AssumedRole/i-<id>`) used in the last 30 days? Established anchors are treated as legitimate; new user-agents on established sessions are the anomaly.

The baseline join is what distinguishes this primitive from Sigma-style stateless rules (`related_work.md` §5). A stateless rule that fires on all IMDS-role events would be either too noisy (fires on every legitimate SDK call) or too specific (misses evasion via user-agent spoofing to `boto3`). The join permits high precision at manageable rule complexity.

## Query Semantics

See `cloudtrail_lake_query.sql`. In prose:

```
For each CloudTrail event E in the last 24h where
    E.userIdentity.type = "AssumedRole"
    AND E.userIdentity.arn matches an EC2-instance-profile role pattern
    (session name starts with "i-")

If E.sourceIPAddress is NOT in the expected egress IP set for that instance
   OR E.userAgent is external and unseen for that role-session in the last 30 days

Fire.
```

The event ID and the anomaly reason (IP mismatch vs. UA mismatch) are captured for downstream alert routing.

## Coverage per Path

See `paths.md` for per-path signature details. Summary:

- **P1**: instance is newly-launched by the attacker; expected egress set is empty (never seen this instance before); any use fires. IP anomaly.
- **P2**: SSRF returns credentials to the attacker's off-box endpoint; the attacker uses them from their own laptop. Source IP is outside the compromised app's VPC. IP anomaly.
- **P6**: attacker extracts credentials from a compromised instance and uses them from a different IP. IP anomaly (and often UA anomaly, since attackers often use curl or Python directly).

All three paths produce IP anomaly at minimum. UA anomaly is a stronger signal for P6 (attackers rarely re-emit the exact same SDK user-agent).

## Preventive Control

`scp_snippet.json` is a Service Control Policy that denies IMDSv1 (metadata-endpoint access without the required token header). IMDSv2 is required across the organisation. This is the strongest structural mitigation:

- Removes P2 entirely (SSRF cannot elevate to IMDS access without the token exchange, which server-side code paths do not perform).
- Weakens P1 and P6 (attackers must still perform the token exchange, but this is trivial once they have shell/exec on the instance).

The SCP is a preventive control paired with, not a replacement for, the detection primitive. IMDSv2 enforcement handles the SSRF case; detection catches the compromised-instance cases where IMDS access is legitimate but subsequent credential use is not.

## Evaluation Summary

Populated after Phase 4 execution. See `evaluation.md`.

## References

- Adversarial evasion analysis: `adversarial_evasion.md`
- AWS↔Azure signal correspondence: `azure_symmetry.md`
- Per-path detection signatures: `paths.md`
- Related-work coverage (which existing tools detect these paths): `../../methodology/related_work.md` §3
