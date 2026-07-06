-- =============================================================================
-- PathTriage Primitive 01 — IMDS Extraction
--
-- Detects: use of EC2-instance-role temporary credentials from a source
-- location (IP or user-agent) inconsistent with the issuing instance's
-- historical egress pattern.
--
-- Covers AWS attack paths: P1 (PassRole+RunInstances), P2 (IMDS SSRF),
-- P6 (Instance Profile Abuse).
--
-- Tunable parameters (see comments):
--   :lookback_hours          — anomaly window (default 24h)
--   :baseline_days           — historical baseline window (default 30d)
--   :min_session_events      — minimum events before a session's UA set
--                              is considered established (default 5)
-- =============================================================================

WITH
-- -----------------------------------------------------------------------------
-- Step 1: identify candidate events — API calls made with EC2 instance-role
-- temporary credentials. The session name pattern "i-<hex>" is the reliable
-- indicator; sessionName is embedded in userIdentity.arn for AssumedRole.
-- -----------------------------------------------------------------------------
candidate_events AS (
    SELECT
        eventID,
        eventTime,
        eventName,
        eventSource,
        awsRegion,
        userIdentity.arn                                             AS caller_arn,
        userIdentity.sessionContext.sessionIssuer.arn                AS role_arn,
        REGEXP_EXTRACT(userIdentity.arn, 'i-[0-9a-f]{8,17}')         AS instance_id,
        sourceIPAddress                                              AS source_ip,
        userAgent                                                    AS user_agent
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND userIdentity.type = 'AssumedRole'
        AND REGEXP_LIKE(userIdentity.arn, 'i-[0-9a-f]{8,17}')
),

-- -----------------------------------------------------------------------------
-- Step 2: for each candidate instance, look up its expected egress IPs.
-- Derived from historical successful RunInstances / DescribeInstances events
-- that recorded the instance's network config.
--
-- In production this table would be populated by a nightly job that snapshots
-- current instance-network state. For evaluation purposes, we derive it
-- inline from the same CloudTrail store using DescribeInstances responses.
-- -----------------------------------------------------------------------------
instance_egress_baseline AS (
    SELECT
        REGEXP_EXTRACT(requestParameters, 'i-[0-9a-f]{8,17}')     AS instance_id,
        JSON_EXTRACT_SCALAR(responseElements,
            '$.instancesSet.items[0].privateIpAddress')             AS private_ip,
        JSON_EXTRACT_SCALAR(responseElements,
            '$.instancesSet.items[0].ipAddress')                    AS public_ip,
        MAX(eventTime)                                              AS observed_at
    FROM cloudtrail_events
    WHERE eventName IN ('RunInstances', 'DescribeInstances')
        AND eventTime >= CURRENT_TIMESTAMP - INTERVAL ':baseline_days' DAY
    GROUP BY 1, 2, 3
),

-- -----------------------------------------------------------------------------
-- Step 3: for each role-session (instance's role + instance id), what
-- user-agents have been seen in the baseline window? Sessions with fewer
-- than :min_session_events observations are NOT considered established —
-- a fresh session cannot itself define its own baseline.
-- -----------------------------------------------------------------------------
session_ua_baseline AS (
    SELECT
        userIdentity.arn                                     AS session_arn,
        userAgent                                            AS ua,
        COUNT(*)                                             AS ua_count
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':baseline_days' DAY
        AND userIdentity.type = 'AssumedRole'
        AND REGEXP_LIKE(userIdentity.arn, 'i-[0-9a-f]{8,17}')
    GROUP BY 1, 2
),

session_established AS (
    SELECT session_arn, SUM(ua_count) AS total_events
    FROM session_ua_baseline
    GROUP BY session_arn
    HAVING SUM(ua_count) >= :min_session_events
),

-- -----------------------------------------------------------------------------
-- Step 4: join candidate events against the baselines. Flag anomalies:
--   ip_anomaly  = source IP not in the instance's expected egress set
--   ua_anomaly  = user-agent unseen for this established session
-- -----------------------------------------------------------------------------
scored_events AS (
    SELECT
        c.eventID,
        c.eventTime,
        c.eventName,
        c.instance_id,
        c.source_ip,
        c.user_agent,
        c.caller_arn,
        c.role_arn,

        -- IP anomaly: no egress record OR IP does not match either private or public
        CASE
            WHEN e.instance_id IS NULL THEN TRUE  -- no baseline: any use is anomaly
            WHEN c.source_ip NOT IN (e.private_ip, e.public_ip) THEN TRUE
            ELSE FALSE
        END AS ip_anomaly,

        -- UA anomaly: session is established, and this UA has never been seen
        CASE
            WHEN se.session_arn IS NULL THEN FALSE  -- unestablished sessions cannot be UA-anomalous
            WHEN NOT EXISTS (
                SELECT 1 FROM session_ua_baseline sub
                WHERE sub.session_arn = c.caller_arn
                    AND sub.ua = c.user_agent
            ) THEN TRUE
            ELSE FALSE
        END AS ua_anomaly

    FROM candidate_events c
    LEFT JOIN instance_egress_baseline e ON c.instance_id = e.instance_id
    LEFT JOIN session_established se ON se.session_arn = c.caller_arn
)

-- -----------------------------------------------------------------------------
-- Step 5: emit fires. Any event with either anomaly flag is a fire.
-- Fires include the anomaly reason for downstream alert routing.
-- -----------------------------------------------------------------------------
SELECT
    eventID,
    eventTime,
    eventName,
    instance_id,
    source_ip,
    user_agent,
    role_arn,
    ip_anomaly,
    ua_anomaly,
    CASE
        WHEN ip_anomaly AND ua_anomaly THEN 'ip+ua'
        WHEN ip_anomaly THEN 'ip'
        WHEN ua_anomaly THEN 'ua'
    END AS anomaly_reason
FROM scored_events
WHERE ip_anomaly OR ua_anomaly
ORDER BY eventTime DESC;
