-- =============================================================================
-- PathTriage Primitive 02 — IAM Modification (Assign)
--
-- Detects: IAM policy assignment (Attach* / Put*) where either
--   (a) caller and target are the same principal (self-attach), OR
--   (b) the newly-assigned policy escalates the target's privilege scope
--       beyond the target's historical maximum.
--
-- Covers AWS attack path: P5 (AttachPolicy Escalation).
--
-- Tunable parameters:
--   :lookback_hours          — anomaly window (default 24h)
--   :baseline_days           — historical baseline window (default 90d)
--   :admin_policy_arns       — list of policies treated as admin-equivalent
-- =============================================================================

WITH
-- -----------------------------------------------------------------------------
-- Step 1: candidate events — IAM policy assignment actions.
-- Both Attach* (managed policies) and Put* (inline policies) count.
-- -----------------------------------------------------------------------------
candidate_events AS (
    SELECT
        eventID,
        eventTime,
        eventName,
        userIdentity.arn                                        AS caller_arn,
        userIdentity.userName                                   AS caller_user,
        COALESCE(
            JSON_EXTRACT_SCALAR(requestParameters, '$.userName'),
            JSON_EXTRACT_SCALAR(requestParameters, '$.roleName'),
            JSON_EXTRACT_SCALAR(requestParameters, '$.groupName')
        )                                                       AS target_name,
        CASE
            WHEN JSON_EXTRACT_SCALAR(requestParameters, '$.userName')  IS NOT NULL THEN 'user'
            WHEN JSON_EXTRACT_SCALAR(requestParameters, '$.roleName')  IS NOT NULL THEN 'role'
            WHEN JSON_EXTRACT_SCALAR(requestParameters, '$.groupName') IS NOT NULL THEN 'group'
        END                                                     AS target_type,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyArn')   AS policy_arn,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyName')  AS inline_policy_name,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyDocument') AS inline_policy_doc,
        CASE
            WHEN eventName IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
                THEN 'managed'
            WHEN eventName IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy')
                THEN 'inline'
        END                                                     AS assign_kind
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName IN (
            'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
            'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy'
        )
        AND (errorCode IS NULL OR errorCode = '')  -- successful calls only
),

-- -----------------------------------------------------------------------------
-- Step 2: identify admin-equivalent policies.
-- AWS-managed policies with broad scope, plus any inline policy whose
-- document contains a wildcard action.
-- -----------------------------------------------------------------------------
admin_managed_policies AS (
    SELECT policy_arn FROM (
        VALUES
            ('arn:aws:iam::aws:policy/AdministratorAccess'),
            ('arn:aws:iam::aws:policy/IAMFullAccess'),
            ('arn:aws:iam::aws:policy/PowerUserAccess'),
            ('arn:aws:iam::aws:policy/AmazonEC2FullAccess'),
            ('arn:aws:iam::aws:policy/AmazonS3FullAccess')
    ) AS t(policy_arn)
),

is_admin_equivalent AS (
    SELECT
        eventID,
        CASE
            WHEN assign_kind = 'managed' AND policy_arn IN (
                SELECT policy_arn FROM admin_managed_policies
            ) THEN TRUE
            WHEN assign_kind = 'inline' AND (
                inline_policy_doc LIKE '%"Action":%"*"%'
                OR inline_policy_doc LIKE '%"Action":%["*"]%'
                OR inline_policy_doc LIKE '%iam:*%'
                OR inline_policy_doc LIKE '%"Resource":%"*"%'
            ) THEN TRUE
            ELSE FALSE
        END AS admin_equivalent
    FROM candidate_events
),

-- -----------------------------------------------------------------------------
-- Step 3: caller history — has this caller granted this policy before?
-- Established policy-manager identities perform assignments routinely; a
-- caller who has never touched this policy before granting an elevated one
-- is anomalous.
-- -----------------------------------------------------------------------------
caller_policy_history AS (
    SELECT
        userIdentity.arn                                     AS caller_arn,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyArn') AS policy_arn,
        COUNT(*)                                             AS grant_count
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':baseline_days' DAY
        AND eventTime <  CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
        AND (errorCode IS NULL OR errorCode = '')
    GROUP BY 1, 2
),

-- -----------------------------------------------------------------------------
-- Step 4: target history — what policies has this target held in the baseline
-- window? Used to score policy-scope escalation.
-- -----------------------------------------------------------------------------
target_policy_history AS (
    SELECT
        COALESCE(
            JSON_EXTRACT_SCALAR(requestParameters, '$.userName'),
            JSON_EXTRACT_SCALAR(requestParameters, '$.roleName'),
            JSON_EXTRACT_SCALAR(requestParameters, '$.groupName')
        )                                                    AS target_name,
        JSON_EXTRACT_SCALAR(requestParameters, '$.policyArn') AS policy_arn,
        MAX(eventTime)                                       AS last_seen
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':baseline_days' DAY
        AND eventTime <  CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
        AND (errorCode IS NULL OR errorCode = '')
    GROUP BY 1, 2
),

target_had_admin_before AS (
    SELECT DISTINCT target_name
    FROM target_policy_history
    WHERE policy_arn IN (SELECT policy_arn FROM admin_managed_policies)
),

-- -----------------------------------------------------------------------------
-- Step 5: score each candidate.
-- -----------------------------------------------------------------------------
scored_events AS (
    SELECT
        c.eventID,
        c.eventTime,
        c.eventName,
        c.caller_arn,
        c.target_name,
        c.target_type,
        c.policy_arn,
        c.inline_policy_name,
        c.assign_kind,
        i.admin_equivalent,

        -- Self-attach: caller principal == target principal.
        -- For users, compare userName directly. For roles, requires assumed-role
        -- context matching; here we use suffix match on the ARN as a heuristic.
        CASE
            WHEN c.target_type = 'user'
                AND c.caller_user = c.target_name THEN TRUE
            WHEN c.target_type = 'role'
                AND c.caller_arn LIKE '%:role/' || c.target_name || '/%' THEN TRUE
            WHEN c.target_type = 'role'
                AND c.caller_arn LIKE '%:assumed-role/' || c.target_name || '/%' THEN TRUE
            ELSE FALSE
        END                                                AS self_attach,

        -- Caller has never granted this managed policy before.
        CASE
            WHEN c.assign_kind = 'managed'
                AND NOT EXISTS (
                    SELECT 1 FROM caller_policy_history h
                    WHERE h.caller_arn = c.caller_arn
                        AND h.policy_arn = c.policy_arn
                ) THEN TRUE
            ELSE FALSE
        END                                                AS unestablished_caller,

        -- Target did not previously hold an admin-equivalent policy.
        CASE
            WHEN c.target_name NOT IN (
                SELECT target_name FROM target_had_admin_before
            ) THEN TRUE
            ELSE FALSE
        END                                                AS target_no_prior_admin

    FROM candidate_events c
    JOIN is_admin_equivalent i ON c.eventID = i.eventID
)

-- -----------------------------------------------------------------------------
-- Step 6: emit fires.
-- Highest confidence: self-attach + admin-equivalent.
-- Medium confidence: unestablished caller + admin-equivalent.
-- Medium confidence: target had no prior admin scope + admin-equivalent
--                    (retroactive elevation of a formerly-scoped identity).
-- -----------------------------------------------------------------------------
SELECT
    eventID,
    eventTime,
    eventName,
    caller_arn,
    target_name,
    target_type,
    policy_arn,
    inline_policy_name,
    assign_kind,
    admin_equivalent,
    self_attach,
    unestablished_caller,
    target_no_prior_admin,
    CASE
        WHEN self_attach AND admin_equivalent THEN 'self_attach_admin'
        WHEN unestablished_caller AND admin_equivalent THEN 'new_caller_grants_admin'
        WHEN target_no_prior_admin AND admin_equivalent THEN 'target_elevated'
    END AS fire_reason,
    CASE
        WHEN self_attach AND admin_equivalent THEN 'high'
        WHEN unestablished_caller AND admin_equivalent THEN 'medium'
        WHEN target_no_prior_admin AND admin_equivalent THEN 'medium'
    END AS confidence
FROM scored_events
WHERE
    (self_attach AND admin_equivalent)
    OR (unestablished_caller AND admin_equivalent)
    OR (target_no_prior_admin AND admin_equivalent)
ORDER BY eventTime DESC;
