# Primitive 04 — Credential Discovery

## Coverage

This primitive covers two verified AWS attack paths:

| Path | Attack | Discovery surface |
|---|---|---|
| P7 | Lambda Env-Var Credential Theft | Long-term IAM access keys stored as Lambda function environment variables; retrieved via `lambda:GetFunctionConfiguration` |
| P8 | S3 Credential Harvest | Long-term IAM access keys stored in bucket objects (`.tfstate`, `.env`, config JSON); retrieved via `s3:GetObject` |

Both paths follow the same structural pattern: an attacker with read access to a **credential-bearing surface** (function config, bucket object) reads that surface, extracts embedded long-term IAM keys, then uses those keys as a separate principal to perform elevated actions. The primitive detects the **read + off-band use correlation**, not the reads individually.

## Detection Rationale

Reading Lambda function configuration and reading S3 objects are extremely high-volume operations — trillions per day across AWS. The read events themselves are not attack signals. Any primitive that fires on `lambda:GetFunctionConfiguration` or `s3:GetObject` alone is unusable.

The attack signature is a **temporal correlation between credential read and credential use**:

1. **Read event**: caller accesses a credential-bearing surface (Lambda env vars via `GetFunctionConfiguration`, or S3 object matching credential-file patterns).
2. **Use event**: within a short window (default 60 minutes), a *different* IAM access key ID appears in CloudTrail performing API calls from an unexpected principal context.

The key insight: the leaked credentials, once used, produce CloudTrail events with `userIdentity.accessKeyId` that has never been used from the reading caller's principal before. This "new access key ID surfaces immediately after credential read" pattern is the primitive's signal.

Baseline joins:

1. **Read baseline**: has this caller accessed this specific function config or bucket object before? Established access patterns are low-risk; first-time access to credential-file-name-matching objects is high-risk.
2. **Access-key-ID novelty**: is the access key ID seen in the use event newly appearing in CloudTrail (first-seen within the last 24h)? Long-lived credentials in legitimate use have long histories; freshly-leaked credentials have empty histories.
3. **Cross-principal appearance**: is the same access key ID appearing under multiple `userIdentity.arn` values? Legitimate credentials belong to one principal; leaked credentials are used by the attacker's principal AND may still be used by the legitimate owner in parallel.

## Baseline-Join Approach

The query joins each candidate read event against the CloudTrail history:

1. **Read side**: filter to `GetFunctionConfiguration` calls returning Lambda functions with non-empty `Environment.Variables`, and `GetObject` calls matching credential-file name patterns (`.tfstate`, `.env`, `credentials*`, `config.json`, `.aws/*`).
2. **Use side**: for each read event, look for API calls in the next 60 minutes where `userIdentity.accessKeyId` was not seen in the caller's 24-hour prior history.
3. **Correlate**: match read caller ↔ subsequent use caller through common source IP or common user-agent within a 5-minute proximity window.

The primitive fires on read events with a correlated use event. Fires without a correlated use are recorded at lower confidence for post-hoc analysis but not surfaced as alerts.

## Query Semantics

See `cloudtrail_lake_query.sql`. In prose:

```
For each CloudTrail event R in the last 24h where
    R.eventName = "GetFunctionConfiguration"
       AND R.responseElements contains "Environment": {...variables...}
    OR
    R.eventName = "GetObject"
       AND R.requestParameters.key matches credential-file patterns

For each subsequent event U within :correlation_window_min minutes where
    U.userIdentity.accessKeyId is NEW (not seen in last 24h across account)
    AND U.userIdentity.arn is DIFFERENT from R.userIdentity.arn

If R and U share source IP OR share user-agent within proximity window:
    → fire (correlated theft + use)

If R alone with no correlated U:
    → record for forensic queue, do not alert
```

## Coverage per Path

See `paths.md`. Summary:

- **P7**: attacker reads Lambda function config, extracts embedded IAM keys, uses them from own principal. Read event: `lambda:GetFunctionConfiguration`. Use event: new access key ID appearing within 60min. Fire reason: `lambda_env_var_correlated`. Confidence: **high**.
- **P8**: attacker reads S3 bucket object containing `.tfstate` or `.env`, extracts embedded keys, uses them. Read event: `s3:GetObject` on matching key pattern. Use event: new access key ID within 60min. Fire reason: `s3_object_correlated`. Confidence: **high**.

## Preventive Control

`scp_snippet.json` enforces two structural preventions:

1. **Deny long-term IAM access keys stored in Lambda env vars** by denying `lambda:UpdateFunctionConfiguration` with request bodies matching `AKIA*` patterns (access key ID prefix).
2. **Deny S3 GetObject to keys matching credential-file patterns** unless the caller holds a specific tag (`credential-read-authorized=true`).

The first prevention closes P7 at the write side (attackers cannot create the misconfiguration); combined with legacy scanning to remove existing exposures, the risk decays to zero over time. The second prevention closes P8 by blocking read access to sensitive file paths.

Both preventions are **content-based**, which means they have known bypasses (encoded keys, non-standard file names). The detection primitive catches these bypasses.

## Evaluation Summary

Populated after Phase 4 execution. See `evaluation.md`.

## References

- Adversarial evasion: `adversarial_evasion.md`
- AWS↔Azure signal correspondence: `azure_symmetry.md`
- Per-path detection signature: `paths.md`
- Related-work coverage: `../../methodology/related_work.md` §3
