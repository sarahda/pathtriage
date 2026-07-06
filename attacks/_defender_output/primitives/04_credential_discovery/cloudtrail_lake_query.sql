-- =============================================================================
-- PathTriage Primitive 04 — Credential Discovery
--
-- Detects: read of a credential-bearing surface (Lambda env vars or S3 object
-- matching credential-file patterns) followed within 60 minutes by the first
-- use of a previously-unseen access key ID from a correlatable caller.
--
-- Covers AWS attack paths: P7 (Lambda env-var theft), P8 (S3 credential harvest).
--
-- Tunable parameters:
--   :lookback_hours              — anomaly window (default 24h)
--   :correlation_window_min      — max minutes between read and use (default 60)
--   :key_id_novelty_window_hours — how far back to look for prior access key
--                                  ID history (default 24h)
-- =============================================================================

WITH
-- -----------------------------------------------------------------------------
-- Step 1: candidate READ events on credential-bearing surfaces.
-- -----------------------------------------------------------------------------
-- Lambda env-var reads: GetFunctionConfiguration returning Environment.Variables
lambda_reads AS (
    SELECT
        eventID                                                 AS read_event_id,
        eventTime                                               AS read_time,
        userIdentity.arn                                        AS reader_arn,
        userIdentity.accessKeyId                                AS reader_access_key,
        sourceIPAddress                                         AS reader_ip,
        userAgent                                               AS reader_ua,
        'lambda' AS discovery_surface,
        JSON_EXTRACT_SCALAR(requestParameters, '$.functionName') AS surface_id,
        NULL AS s3_key_pattern
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName = 'GetFunctionConfiguration'
        AND (errorCode IS NULL OR errorCode = '')
        AND responseElements LIKE '%"Environment"%"Variables"%'
),

-- S3 credential-file reads: GetObject on keys matching known credential patterns
s3_reads AS (
    SELECT
        eventID                                                 AS read_event_id,
        eventTime                                               AS read_time,
        userIdentity.arn                                        AS reader_arn,
        userIdentity.accessKeyId                                AS reader_access_key,
        sourceIPAddress                                         AS reader_ip,
        userAgent                                               AS reader_ua,
        's3' AS discovery_surface,
        CONCAT(
            JSON_EXTRACT_SCALAR(requestParameters, '$.bucketName'),
            '/',
            JSON_EXTRACT_SCALAR(requestParameters, '$.key')
        ) AS surface_id,
        JSON_EXTRACT_SCALAR(requestParameters, '$.key') AS s3_key_pattern
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName = 'GetObject'
        AND (errorCode IS NULL OR errorCode = '')
        AND (
            LOWER(JSON_EXTRACT_SCALAR(requestParameters, '$.key')) LIKE '%.tfstate%'
            OR LOWER(JSON_EXTRACT_SCALAR(requestParameters, '$.key')) LIKE '%.env%'
            OR LOWER(JSON_EXTRACT_SCALAR(requestParameters, '$.key')) LIKE '%credentials%'
            OR LOWER(JSON_EXTRACT_SCALAR(requestParameters, '$.key')) LIKE '%.aws/%'
            OR LOWER(JSON_EXTRACT_SCALAR(requestParameters, '$.key')) LIKE '%config.json%'
            OR LOWER(JSON_EXTRACT_SCALAR(requestParameters, '$.key')) LIKE '%secrets%'
        )
),

all_reads AS (
    SELECT * FROM lambda_reads
    UNION ALL
    SELECT * FROM s3_reads
),

-- -----------------------------------------------------------------------------
-- Step 2: read baseline — has this reader accessed this surface before?
-- First-time access to a credential-file-matching surface is high-risk.
-- -----------------------------------------------------------------------------
reader_surface_history AS (
    SELECT
        userIdentity.arn AS reader_arn,
        CASE
            WHEN eventName = 'GetFunctionConfiguration' THEN
                JSON_EXTRACT_SCALAR(requestParameters, '$.functionName')
            WHEN eventName = 'GetObject' THEN
                CONCAT(
                    JSON_EXTRACT_SCALAR(requestParameters, '$.bucketName'),
                    '/',
                    JSON_EXTRACT_SCALAR(requestParameters, '$.key')
                )
        END AS surface_id,
        MIN(eventTime) AS first_access
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
                     - INTERVAL '30' DAY  -- 30d prior history
        AND eventName IN ('GetFunctionConfiguration', 'GetObject')
        AND (errorCode IS NULL OR errorCode = '')
    GROUP BY 1, 2
),

first_time_reads AS (
    SELECT
        r.read_event_id,
        r.reader_arn,
        r.surface_id,
        r.read_time,
        CASE
            WHEN h.first_access IS NULL THEN TRUE
            WHEN h.first_access >= r.read_time - INTERVAL '1' MINUTE THEN TRUE
            ELSE FALSE
        END AS first_time_access
    FROM all_reads r
    LEFT JOIN reader_surface_history h
        ON r.reader_arn = h.reader_arn
        AND r.surface_id = h.surface_id
),

-- -----------------------------------------------------------------------------
-- Step 3: identify NEW access key IDs — first appearance within
-- :key_id_novelty_window_hours.
-- -----------------------------------------------------------------------------
access_key_first_seen AS (
    SELECT
        userIdentity.accessKeyId AS access_key_id,
        MIN(eventTime)           AS first_seen
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
                     - INTERVAL ':key_id_novelty_window_hours' HOUR
        AND userIdentity.accessKeyId IS NOT NULL
        AND userIdentity.accessKeyId != ''
    GROUP BY 1
),

new_key_uses AS (
    SELECT
        e.eventID                       AS use_event_id,
        e.eventTime                     AS use_time,
        e.eventName                     AS use_event_name,
        e.userIdentity.arn              AS user_arn,
        e.userIdentity.accessKeyId      AS access_key_id,
        e.sourceIPAddress               AS use_ip,
        e.userAgent                     AS use_ua,
        fs.first_seen                   AS key_first_seen
    FROM cloudtrail_events e
    JOIN access_key_first_seen fs
        ON e.userIdentity.accessKeyId = fs.access_key_id
    WHERE
        e.eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND fs.first_seen >= CURRENT_TIMESTAMP
            - INTERVAL ':key_id_novelty_window_hours' HOUR
        -- Novelty condition: first-seen is within the novelty window
),

-- -----------------------------------------------------------------------------
-- Step 4: correlate reads with new-key uses.
-- Matching heuristics:
--   - use happens within :correlation_window_min after read
--   - use is by a different principal (userIdentity.arn) than reader
--   - shared source IP OR shared user-agent between reader and user
-- -----------------------------------------------------------------------------
correlated_pairs AS (
    SELECT
        r.read_event_id,
        r.read_time,
        r.reader_arn,
        r.reader_ip,
        r.reader_ua,
        r.discovery_surface,
        r.surface_id,
        u.use_event_id,
        u.use_time,
        u.user_arn,
        u.access_key_id,
        u.use_ip,
        u.use_ua,
        TIMESTAMP_DIFF(u.use_time, r.read_time, MINUTE) AS lag_minutes,
        CASE
            WHEN r.reader_ip = u.use_ip THEN TRUE
            ELSE FALSE
        END AS shared_ip,
        CASE
            WHEN r.reader_ua = u.use_ua THEN TRUE
            ELSE FALSE
        END AS shared_ua
    FROM all_reads r
    JOIN new_key_uses u
        ON u.use_time BETWEEN r.read_time
            AND r.read_time + INTERVAL ':correlation_window_min' MINUTE
        AND u.user_arn != r.reader_arn
    WHERE
        r.reader_ip = u.use_ip
        OR r.reader_ua = u.use_ua
),

-- -----------------------------------------------------------------------------
-- Step 5: score and emit fires.
-- -----------------------------------------------------------------------------
scored_events AS (
    SELECT
        cp.read_event_id,
        cp.use_event_id,
        cp.read_time,
        cp.use_time,
        cp.reader_arn,
        cp.user_arn,
        cp.access_key_id,
        cp.discovery_surface,
        cp.surface_id,
        cp.lag_minutes,
        cp.shared_ip,
        cp.shared_ua,
        ftr.first_time_access,
        CASE
            WHEN cp.discovery_surface = 'lambda'
                AND ftr.first_time_access
                AND (cp.shared_ip OR cp.shared_ua)
                THEN 'lambda_env_var_correlated_novel'
            WHEN cp.discovery_surface = 'lambda'
                AND (cp.shared_ip OR cp.shared_ua)
                THEN 'lambda_env_var_correlated'
            WHEN cp.discovery_surface = 's3'
                AND ftr.first_time_access
                AND (cp.shared_ip OR cp.shared_ua)
                THEN 's3_object_correlated_novel'
            WHEN cp.discovery_surface = 's3'
                AND (cp.shared_ip OR cp.shared_ua)
                THEN 's3_object_correlated'
        END AS fire_reason,
        CASE
            WHEN ftr.first_time_access
                AND cp.shared_ip AND cp.shared_ua THEN 'high'
            WHEN ftr.first_time_access
                AND (cp.shared_ip OR cp.shared_ua) THEN 'high'
            WHEN cp.shared_ip AND cp.shared_ua THEN 'medium'
            WHEN cp.shared_ip OR cp.shared_ua THEN 'low'
        END AS confidence
    FROM correlated_pairs cp
    LEFT JOIN first_time_reads ftr
        ON cp.read_event_id = ftr.read_event_id
)

-- -----------------------------------------------------------------------------
-- Step 6: final output.
-- -----------------------------------------------------------------------------
SELECT
    read_event_id,
    use_event_id,
    read_time,
    use_time,
    reader_arn,
    user_arn,
    access_key_id,
    discovery_surface,
    surface_id,
    lag_minutes,
    shared_ip,
    shared_ua,
    first_time_access,
    fire_reason,
    confidence
FROM scored_events
WHERE fire_reason IS NOT NULL
ORDER BY read_time DESC;
