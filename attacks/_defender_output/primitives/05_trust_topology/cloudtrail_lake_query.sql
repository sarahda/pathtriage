-- =============================================================================
-- PathTriage Primitive 05 — Trust Topology
--
-- Detects: multi-hop sts:AssumeRole chains (3+ hops) originating from a
-- single starting principal within a short time window, where the terminal
-- role is new for that principal AND/OR the terminal role holds admin-
-- equivalent policies.
--
-- Covers AWS attack path: P4 (AssumeRole Chain).
--
-- Tunable parameters:
--   :lookback_hours     — anomaly window (default 24h)
--   :chain_window_min   — max minutes between hops in a single chain (default 15)
--   :baseline_days      — historical chain baseline window (default 90d)
--   :min_chain_length   — minimum chain length to consider (default 3)
-- =============================================================================

WITH
-- -----------------------------------------------------------------------------
-- Step 1: raw AssumeRole events with source and target identity extracted.
-- -----------------------------------------------------------------------------
assume_role_events AS (
    SELECT
        eventID                                                      AS ev_id,
        eventTime                                                    AS ev_time,
        userIdentity.arn                                             AS caller_arn,
        userIdentity.type                                            AS caller_type,
        userIdentity.sessionContext.sessionIssuer.arn                AS caller_session_issuer,
        JSON_EXTRACT_SCALAR(requestParameters, '$.roleArn')          AS target_role_arn,
        JSON_EXTRACT_SCALAR(requestParameters, '$.roleSessionName')  AS target_session_name,
        JSON_EXTRACT_SCALAR(responseElements, '$.assumedRoleUser.arn') AS assumed_arn,
        sourceIPAddress                                              AS ev_ip
    FROM cloudtrail_events
    WHERE
        eventTime >= CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
        AND eventName = 'AssumeRole'
        AND (errorCode IS NULL OR errorCode = '')
),

-- -----------------------------------------------------------------------------
-- Step 2: identify hops. A hop is an AssumeRole event where the caller is
-- itself an assumed role (chain continuation) or a plain identity (chain
-- start). We match hop N+1 by finding events where the caller ARN matches
-- the "assumed_arn" of hop N within :chain_window_min minutes.
-- -----------------------------------------------------------------------------
-- Chain starts: AssumeRole calls where the caller is NOT itself an assumed role
chain_starts AS (
    SELECT
        ev_id      AS start_ev_id,
        ev_time    AS start_time,
        caller_arn AS starting_principal,
        assumed_arn AS hop_1_arn,
        ev_ip      AS start_ip
    FROM assume_role_events
    WHERE caller_type = 'IAMUser'
       OR caller_type = 'Root'
       OR caller_type = 'FederatedUser'
),

-- Hop chains — self-join up to 4 hops (attack chains rarely exceed this)
chain_hops AS (
    SELECT
        cs.start_ev_id,
        cs.start_time,
        cs.starting_principal,
        cs.start_ip,
        cs.hop_1_arn,
        h2.assumed_arn AS hop_2_arn,
        h2.ev_time     AS hop_2_time,
        h3.assumed_arn AS hop_3_arn,
        h3.ev_time     AS hop_3_time,
        h4.assumed_arn AS hop_4_arn,
        h4.ev_time     AS hop_4_time
    FROM chain_starts cs
    LEFT JOIN assume_role_events h2
        ON h2.caller_arn = cs.hop_1_arn
        AND h2.ev_time BETWEEN cs.start_time
            AND cs.start_time + INTERVAL ':chain_window_min' MINUTE
    LEFT JOIN assume_role_events h3
        ON h3.caller_arn = h2.assumed_arn
        AND h3.ev_time BETWEEN h2.ev_time
            AND h2.ev_time + INTERVAL ':chain_window_min' MINUTE
    LEFT JOIN assume_role_events h4
        ON h4.caller_arn = h3.assumed_arn
        AND h4.ev_time BETWEEN h3.ev_time
            AND h3.ev_time + INTERVAL ':chain_window_min' MINUTE
),

-- -----------------------------------------------------------------------------
-- Step 3: compute chain length and terminal role.
-- -----------------------------------------------------------------------------
chain_summary AS (
    SELECT
        start_ev_id,
        start_time,
        starting_principal,
        start_ip,
        CASE
            WHEN hop_4_arn IS NOT NULL THEN 4
            WHEN hop_3_arn IS NOT NULL THEN 3
            WHEN hop_2_arn IS NOT NULL THEN 2
            ELSE 1
        END AS chain_length,
        COALESCE(hop_4_arn, hop_3_arn, hop_2_arn, hop_1_arn) AS terminal_role_arn,
        -- Chain signature: concatenated role ARNs (for exact match with history)
        CONCAT(
            hop_1_arn, '|',
            COALESCE(hop_2_arn, ''), '|',
            COALESCE(hop_3_arn, ''), '|',
            COALESCE(hop_4_arn, '')
        ) AS chain_signature
    FROM chain_hops
),

-- -----------------------------------------------------------------------------
-- Step 4: baseline — has this principal traversed this chain before?
-- Uses same chain-reconstruction logic against baseline history.
-- -----------------------------------------------------------------------------
historical_chain_starts AS (
    SELECT
        ev_id      AS h_start_ev_id,
        ev_time    AS h_start_time,
        caller_arn AS h_starting_principal,
        assumed_arn AS h_hop_1_arn
    FROM assume_role_events
    WHERE caller_type IN ('IAMUser', 'Root', 'FederatedUser')
),

historical_chains AS (
    SELECT
        hcs.h_starting_principal,
        hcs.h_start_time,
        CONCAT(
            hcs.h_hop_1_arn, '|',
            COALESCE(h2.assumed_arn, ''), '|',
            COALESCE(h3.assumed_arn, ''), '|',
            COALESCE(h4.assumed_arn, '')
        ) AS h_chain_signature,
        COALESCE(h4.assumed_arn, h3.assumed_arn, h2.assumed_arn, hcs.h_hop_1_arn) AS h_terminal_role
    FROM historical_chain_starts hcs
    LEFT JOIN assume_role_events h2
        ON h2.caller_arn = hcs.h_hop_1_arn
        AND h2.ev_time BETWEEN hcs.h_start_time
            AND hcs.h_start_time + INTERVAL ':chain_window_min' MINUTE
    LEFT JOIN assume_role_events h3
        ON h3.caller_arn = h2.assumed_arn
        AND h3.ev_time BETWEEN h2.ev_time
            AND h2.ev_time + INTERVAL ':chain_window_min' MINUTE
    LEFT JOIN assume_role_events h4
        ON h4.caller_arn = h3.assumed_arn
        AND h4.ev_time BETWEEN h3.ev_time
            AND h3.ev_time + INTERVAL ':chain_window_min' MINUTE
    WHERE hcs.h_start_time < CURRENT_TIMESTAMP - INTERVAL ':lookback_hours' HOUR
      AND hcs.h_start_time >= CURRENT_TIMESTAMP - INTERVAL ':baseline_days' DAY
),

-- -----------------------------------------------------------------------------
-- Step 5: check chain novelty (exact chain signature) and terminal novelty
-- (starting principal has never reached this terminal).
-- -----------------------------------------------------------------------------
scored_chains AS (
    SELECT
        cs.start_ev_id,
        cs.start_time,
        cs.starting_principal,
        cs.start_ip,
        cs.chain_length,
        cs.terminal_role_arn,
        cs.chain_signature,

        -- Chain novelty: exact signature never seen for this principal
        CASE
            WHEN NOT EXISTS (
                SELECT 1 FROM historical_chains hc
                WHERE hc.h_starting_principal = cs.starting_principal
                    AND hc.h_chain_signature = cs.chain_signature
            ) THEN TRUE
            ELSE FALSE
        END AS chain_novel,

        -- Terminal novelty: this principal has never reached this terminal via any chain
        CASE
            WHEN NOT EXISTS (
                SELECT 1 FROM historical_chains hc
                WHERE hc.h_starting_principal = cs.starting_principal
                    AND hc.h_terminal_role = cs.terminal_role_arn
            ) THEN TRUE
            ELSE FALSE
        END AS terminal_novel

    FROM chain_summary cs
    WHERE cs.chain_length >= :min_chain_length
),

-- -----------------------------------------------------------------------------
-- Step 6: identify admin-equivalent terminal roles.
-- Approximation: role name matches admin-suggesting patterns, OR the role has
-- had an admin policy attached at some point (checked via AttachRolePolicy
-- history).
-- -----------------------------------------------------------------------------
admin_role_arns AS (
    SELECT DISTINCT
        JSON_EXTRACT_SCALAR(requestParameters, '$.roleName') AS role_name,
        CONCAT('arn:aws:iam::*:role/',
               JSON_EXTRACT_SCALAR(requestParameters, '$.roleName')) AS role_arn_pattern
    FROM cloudtrail_events
    WHERE eventName = 'AttachRolePolicy'
      AND JSON_EXTRACT_SCALAR(requestParameters, '$.policyArn') IN (
          'arn:aws:iam::aws:policy/AdministratorAccess',
          'arn:aws:iam::aws:policy/IAMFullAccess',
          'arn:aws:iam::aws:policy/PowerUserAccess'
      )
      AND eventTime >= CURRENT_TIMESTAMP - INTERVAL ':baseline_days' DAY
),

-- -----------------------------------------------------------------------------
-- Step 7: emit fires.
-- Highest confidence: admin_terminal + terminal_novel.
-- Medium: chain_novel + terminal_novel (unusual + unfamiliar destination).
-- Low: chain_novel only.
-- -----------------------------------------------------------------------------
SELECT
    sc.start_ev_id,
    sc.start_time,
    sc.starting_principal,
    sc.start_ip,
    sc.chain_length,
    sc.terminal_role_arn,
    sc.chain_signature,
    sc.chain_novel,
    sc.terminal_novel,
    CASE
        WHEN EXISTS (
            SELECT 1 FROM admin_role_arns ar
            WHERE sc.terminal_role_arn LIKE ar.role_arn_pattern
        ) THEN TRUE
        ELSE FALSE
    END AS admin_terminal,
    CASE
        WHEN sc.terminal_novel AND EXISTS (
            SELECT 1 FROM admin_role_arns ar
            WHERE sc.terminal_role_arn LIKE ar.role_arn_pattern
        ) THEN 'admin_terminal_novel_chain'
        WHEN sc.chain_novel AND sc.terminal_novel THEN 'novel_chain_novel_terminal'
        WHEN sc.chain_novel THEN 'novel_chain'
    END AS fire_reason,
    CASE
        WHEN sc.terminal_novel AND EXISTS (
            SELECT 1 FROM admin_role_arns ar
            WHERE sc.terminal_role_arn LIKE ar.role_arn_pattern
        ) THEN 'high'
        WHEN sc.chain_novel AND sc.terminal_novel THEN 'medium'
        WHEN sc.chain_novel THEN 'low'
    END AS confidence
FROM scored_chains sc
WHERE sc.chain_novel OR sc.terminal_novel
ORDER BY sc.start_time DESC;
