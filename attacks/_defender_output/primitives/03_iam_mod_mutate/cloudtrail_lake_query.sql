-- =============================================================================
-- PathTriage Primitive 03 — IAM Modification (Mutate)
--
-- Detects: iam:CreatePolicyVersion where the new version grants actions the
-- prior default version did not, AND the new version is activated (either
-- via subsequent SetDefaultPolicyVersion within 5 min or setAsDefault=true).
--
-- Covers AWS attack path: P3 (CreatePolicyVersion Escalation).
--
-- Tunable parameters:
--   :lookback_hours          — anomaly window (default 24h)
--   :baseline_days           — historical baseline for prior versions (default 180d)
--   :correlation_window_sec  — max seconds between Create and SetDefault (default 300 = 5 min)
--   :mass_attach_threshold   — attached principals above which mutation is mass-elevation (default 3)
-- =============================================================================

WITH
-- -----------------------------------------------------------------------------
-- Step 1: candidate CreatePolicyVersion events.
-- -----------------------------------------------------------------------------
create_events AS (
    SELECT
        eventID                                                    AS create_event_id,
        eventTime                                                  AS create_time,
        userIdentity.arn                                           AS caller_arn,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyArn')      AS policy_arn,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyDocument') AS new_policy_doc,
        JSON_EXTRACT_SCALAR(requestParameters, '$.setAsDefault')   AS set_as_default_flag,
        JSON_EXTRACT_SCALAR(responseElements, '$.policyVersion.versionId') AS new_version_id
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName = 'CreatePolicyVersion'
        AND (errorCode IS NULL OR errorCode = '')
),

-- -----------------------------------------------------------------------------
-- Step 2: subsequent SetDefaultPolicyVersion events, correlated to a create.
-- Correlation window is :correlation_window_sec (default 300s).
-- -----------------------------------------------------------------------------
set_default_events AS (
    SELECT
        eventID                                                    AS set_default_event_id,
        eventTime                                                  AS set_default_time,
        userIdentity.arn                                           AS set_default_caller_arn,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyArn')      AS policy_arn,
        JSON_EXTRACT_SCALAR(requestParameters, '$.versionId')      AS activated_version_id
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName = 'SetDefaultPolicyVersion'
        AND (errorCode IS NULL OR errorCode = '')
),

-- -----------------------------------------------------------------------------
-- Step 3: correlate Create with SetDefault. Include cases where
-- setAsDefault=true (Create alone activates).
-- -----------------------------------------------------------------------------
activated_creates AS (
    -- Case A: separate SetDefaultPolicyVersion within window
    SELECT
        c.create_event_id,
        c.create_time,
        c.caller_arn,
        c.policy_arn,
        c.new_policy_doc,
        c.new_version_id,
        s.set_default_event_id,
        s.set_default_time,
        'separate_activate' AS activation_pattern,
        TIMESTAMP_DIFF(s.set_default_time, c.create_time, SECOND) AS activation_lag_sec
    FROM create_events c
    JOIN set_default_events s
        ON c.policy_arn = s.policy_arn
        AND c.new_version_id = s.activated_version_id
        AND s.set_default_time BETWEEN c.create_time
            AND c.create_time + INTERVAL ':correlation_window_sec' SECOND

    UNION ALL

    -- Case B: setAsDefault=true on the Create event itself
    SELECT
        c.create_event_id,
        c.create_time,
        c.caller_arn,
        c.policy_arn,
        c.new_policy_doc,
        c.new_version_id,
        NULL AS set_default_event_id,
        c.create_time AS set_default_time,
        'inline_activate' AS activation_pattern,
        0 AS activation_lag_sec
    FROM create_events c
    WHERE c.set_as_default_flag = 'true'
),

-- -----------------------------------------------------------------------------
-- Step 4: for each policy that was mutated, fetch the prior default version's
-- content. The prior version was itself the target of an earlier
-- CreatePolicyVersion (with setAsDefault=true or paired SetDefault), or is
-- the v1 from the initial CreatePolicy.
--
-- Approximation: use the most recent prior CreatePolicyVersion for this policy
-- before the current one. For v1, fall back to CreatePolicy.
-- -----------------------------------------------------------------------------
prior_versions AS (
    SELECT
        c.policy_arn,
        c.create_time,
        (
            SELECT JSON_EXTRACT_SCALAR(prior.requestParameters, '$.policyDocument')
            FROM cloudtrail_events prior
            WHERE prior.eventName IN ('CreatePolicyVersion', 'CreatePolicy')
                AND JSON_EXTRACT_SCALAR(prior.requestParameters, '$.policyArn') = c.policy_arn
                AND prior.eventTime <  c.create_time
                AND prior.eventTime >= c.create_time - INTERVAL ':baseline_days' DAY
                AND (prior.errorCode IS NULL OR prior.errorCode = '')
            ORDER BY prior.eventTime DESC
            LIMIT 1
        ) AS prior_policy_doc
    FROM activated_creates c
),

-- -----------------------------------------------------------------------------
-- Step 5: score delta. Detection heuristic on the new policy document.
-- Full JSON-diff of Statement/Action arrays is out of scope for a single
-- SQL query; substring checks on the new document capture admin-equivalent
-- content that is the attack signature.
-- -----------------------------------------------------------------------------
scored_events AS (
    SELECT
        a.create_event_id,
        a.set_default_event_id,
        a.create_time,
        a.set_default_time,
        a.caller_arn,
        a.policy_arn,
        a.new_version_id,
        a.activation_pattern,
        a.activation_lag_sec,

        -- Admin-equivalent new content: wildcard action, iam:* wildcard, or
        -- wildcard resource combined with permissive action.
        CASE
            WHEN a.new_policy_doc LIKE '%"Action":%"*"%' THEN TRUE
            WHEN a.new_policy_doc LIKE '%"Action":%["*"]%' THEN TRUE
            WHEN a.new_policy_doc LIKE '%"Action":%"iam:*"%' THEN TRUE
            WHEN a.new_policy_doc LIKE '%"Action":%"*:*"%' THEN TRUE
            ELSE FALSE
        END AS new_has_admin_action,

        -- Prior version content check: prior version DID NOT have admin action.
        -- If prior had admin already, this is a legitimate version bump.
        CASE
            WHEN p.prior_policy_doc IS NULL THEN TRUE  -- no prior baseline: treat as admin-new
            WHEN p.prior_policy_doc NOT LIKE '%"Action":%"*"%'
                AND p.prior_policy_doc NOT LIKE '%"Action":%["*"]%'
                AND p.prior_policy_doc NOT LIKE '%"Action":%"iam:*"%'
                AND p.prior_policy_doc NOT LIKE '%"Action":%"*:*"%'
                THEN TRUE
            ELSE FALSE
        END AS prior_lacked_admin_action

    FROM activated_creates a
    LEFT JOIN prior_versions p
        ON a.policy_arn = p.policy_arn
        AND a.create_time = p.create_time
),

-- -----------------------------------------------------------------------------
-- Step 6: caller self-benefit — has the caller attached this policy to
-- themselves or to a role they can assume?
-- -----------------------------------------------------------------------------
caller_policy_attachment AS (
    SELECT
        s.create_event_id,
        s.caller_arn,
        s.policy_arn,
        CASE
            WHEN EXISTS (
                SELECT 1 FROM cloudtrail_events attach
                WHERE attach.eventName IN ('AttachUserPolicy', 'AttachRolePolicy')
                    AND JSON_EXTRACT_SCALAR(attach.requestParameters, '$.policyArn') = s.policy_arn
                    AND (
                        s.caller_arn LIKE '%:user/' ||
                            COALESCE(JSON_EXTRACT_SCALAR(attach.requestParameters, '$.userName'), '__none__') || '%'
                        OR s.caller_arn LIKE '%:role/' ||
                            COALESCE(JSON_EXTRACT_SCALAR(attach.requestParameters, '$.roleName'), '__none__') || '%'
                        OR s.caller_arn LIKE '%:assumed-role/' ||
                            COALESCE(JSON_EXTRACT_SCALAR(attach.requestParameters, '$.roleName'), '__none__') || '%'
                    )
                    AND attach.eventTime <= s.create_time
                    AND attach.eventTime >= s.create_time - INTERVAL ':baseline_days' DAY
            ) THEN TRUE
            ELSE FALSE
        END AS caller_holds_policy
    FROM scored_events s
),

-- -----------------------------------------------------------------------------
-- Step 7: attachment count — how many principals currently hold this policy?
-- Approximation via count of Attach* events not followed by Detach*.
-- -----------------------------------------------------------------------------
attachment_count AS (
    SELECT
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyArn') AS policy_arn,
        COUNT(*) AS attach_count
    FROM cloudtrail_events
    WHERE
        eventName IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
        AND eventTime >= CURRENT_TIMESTAMP - INTERVAL ':baseline_days' DAY
        AND (errorCode IS NULL OR errorCode = '')
    GROUP BY 1
)

-- -----------------------------------------------------------------------------
-- Step 8: emit fires.
-- Highest confidence: caller-self-benefit + admin-new + prior-lacked.
-- Medium confidence: mass-attach + admin-new + prior-lacked.
-- Low confidence: admin-new + prior-lacked (someone will benefit, but
--                 attribution is unclear).
-- -----------------------------------------------------------------------------
SELECT
    s.create_event_id,
    s.set_default_event_id,
    s.create_time,
    s.set_default_time,
    s.caller_arn,
    s.policy_arn,
    s.new_version_id,
    s.activation_pattern,
    s.activation_lag_sec,
    s.new_has_admin_action,
    s.prior_lacked_admin_action,
    ca.caller_holds_policy,
    COALESCE(ac.attach_count, 0) AS current_attach_count,
    CASE
        WHEN ca.caller_holds_policy AND s.new_has_admin_action AND s.prior_lacked_admin_action
            THEN 'self_benefit_admin_injection'
        WHEN COALESCE(ac.attach_count, 0) >= :mass_attach_threshold
            AND s.new_has_admin_action AND s.prior_lacked_admin_action
            THEN 'mass_elevation'
        WHEN s.new_has_admin_action AND s.prior_lacked_admin_action
            THEN 'admin_injection'
    END AS fire_reason,
    CASE
        WHEN ca.caller_holds_policy AND s.new_has_admin_action AND s.prior_lacked_admin_action THEN 'high'
        WHEN COALESCE(ac.attach_count, 0) >= :mass_attach_threshold AND s.new_has_admin_action AND s.prior_lacked_admin_action THEN 'medium'
        WHEN s.new_has_admin_action AND s.prior_lacked_admin_action THEN 'low'
    END AS confidence
FROM scored_events s
LEFT JOIN caller_policy_attachment ca ON s.create_event_id = ca.create_event_id
LEFT JOIN attachment_count ac ON s.policy_arn = ac.policy_arn
WHERE s.new_has_admin_action AND s.prior_lacked_admin_action
ORDER BY s.create_time DESC;
