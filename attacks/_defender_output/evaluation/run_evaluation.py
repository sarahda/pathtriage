#!/usr/bin/env python3
"""
PathTriage Defender-Output Phase 4 — Primitive Evaluation
=========================================================

Executes 5 detection primitives against the combined (baseline + positive)
CloudTrail corpus using DuckDB, scores TP/FP/FN, and emits results per
primitive plus an aggregate summary.

Simplified DuckDB queries encode the essential detection heuristic of each
primitive; the authoritative CTL queries at primitives/NN_*/cloudtrail_lake_query.sql
retain full baseline-join semantics for production deployment.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import duckdb


ACCOUNT_ID  = "559292738121"
EVAL_START  = "TIMESTAMP '2026-07-06 22:00:00'"
EVAL_NOW    = "TIMESTAMP '2026-07-07 22:00:00'"

COVERAGE: Dict[str, List[str]] = {
    "01": ["P1", "P2", "P6"],
    "02": ["P5"],
    "03": ["P3"],
    "04": ["P7", "P8"],
    "05": ["P4"],
}


QUERIES: Dict[str, str] = {

    "01": f"""
        SELECT event_id, event_time, event_name, caller_arn, src_ip, ua, ip_anomaly, ua_anomaly
        FROM (
            SELECT
                eventID::VARCHAR                                              AS event_id,
                eventTime                                                     AS event_time,
                eventName                                                     AS event_name,
                userIdentity.arn                                              AS caller_arn,
                sourceIPAddress                                               AS src_ip,
                userAgent                                                     AS ua,
                CASE
                    WHEN sourceIPAddress NOT IN ('52.62.100.10','52.62.100.11')
                    THEN TRUE ELSE FALSE
                END                                                           AS ip_anomaly,
                CASE
                    WHEN userAgent NOT LIKE '%exec-env/AWS_EC2%'
                    THEN TRUE ELSE FALSE
                END                                                           AS ua_anomaly
            FROM ct
            WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
              AND userIdentity.type = 'AssumedRole'
              AND regexp_matches(userIdentity.arn, 'i-[0-9a-f]{{17}}$')
        ) t
        WHERE ip_anomaly OR ua_anomaly
    """,

    "02": f"""
        SELECT
            eventID::VARCHAR                                              AS event_id,
            eventTime                                                     AS event_time,
            eventName                                                     AS event_name,
            userIdentity.arn                                              AS caller_arn,
            json_extract_string(requestParameters['policyArn'], '$')      AS policy_arn,
            COALESCE(
                json_extract_string(requestParameters['userName'],  '$'),
                json_extract_string(requestParameters['roleName'],  '$'),
                json_extract_string(requestParameters['groupName'], '$')
            )                                                             AS target_name
        FROM ct
        WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
          AND eventName IN ('AttachUserPolicy','AttachRolePolicy','AttachGroupPolicy',
                            'PutUserPolicy','PutRolePolicy','PutGroupPolicy')
          AND (
              json_extract_string(requestParameters['policyArn'], '$') IN (
                  'arn:aws:iam::aws:policy/AdministratorAccess',
                  'arn:aws:iam::aws:policy/IAMFullAccess',
                  'arn:aws:iam::aws:policy/PowerUserAccess',
                  'arn:aws:iam::aws:policy/AmazonEC2FullAccess',
                  'arn:aws:iam::aws:policy/AmazonS3FullAccess'
              )
              OR json_extract_string(requestParameters['policyDocument'], '$') LIKE '%"Action":"*"%'
              OR json_extract_string(requestParameters['policyDocument'], '$') LIKE '%"Action":"iam:*"%'
          )
    """,

    "03": f"""
        SELECT
            eventID::VARCHAR                                              AS event_id,
            eventTime                                                     AS event_time,
            eventName                                                     AS event_name,
            userIdentity.arn                                              AS caller_arn,
            json_extract_string(requestParameters['policyArn'], '$')      AS policy_arn,
            json_extract_string(requestParameters['policyDocument'], '$') AS new_doc,
            json_extract_string(requestParameters['setAsDefault'], '$')   AS activate_flag
        FROM ct
        WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
          AND eventName = 'CreatePolicyVersion'
          AND (
              json_extract_string(requestParameters['policyDocument'], '$') LIKE '%"Action":"*"%'
              OR json_extract_string(requestParameters['policyDocument'], '$') LIKE '%"Action":["*"]%'
              OR json_extract_string(requestParameters['policyDocument'], '$') LIKE '%"Action":"iam:*"%'
          )
    """,

    "04": f"""
        WITH reads AS (
            SELECT
                eventID::VARCHAR         AS read_event_id,
                eventTime                AS read_time,
                userIdentity.arn         AS reader_arn,
                sourceIPAddress          AS reader_ip,
                'lambda'                 AS surface,
                json_extract_string(requestParameters['functionName'], '$') AS surface_id
            FROM ct
            WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
              AND eventName = 'GetFunctionConfiguration'

            UNION ALL

            SELECT
                eventID::VARCHAR         AS read_event_id,
                eventTime                AS read_time,
                userIdentity.arn         AS reader_arn,
                sourceIPAddress          AS reader_ip,
                's3'                     AS surface,
                json_extract_string(requestParameters['key'], '$') AS surface_id
            FROM ct
            WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
              AND eventName = 'GetObject'
              AND (
                  LOWER(json_extract_string(requestParameters['key'], '$')) LIKE '%.tfstate%'
                  OR LOWER(json_extract_string(requestParameters['key'], '$')) LIKE '%.env%'
                  OR LOWER(json_extract_string(requestParameters['key'], '$')) LIKE '%credentials%'
                  OR LOWER(json_extract_string(requestParameters['key'], '$')) LIKE '%secrets%'
                  OR LOWER(json_extract_string(requestParameters['key'], '$')) LIKE '%.aws/%'
              )
        ),
        key_uses AS (
            SELECT
                eventID::VARCHAR         AS use_event_id,
                eventTime                AS use_time,
                userIdentity.arn         AS user_arn,
                userIdentity.accessKeyId AS access_key,
                sourceIPAddress          AS use_ip
            FROM ct
            WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
              AND userIdentity.accessKeyId IS NOT NULL
              AND userIdentity.accessKeyId != ''
        )
        SELECT
            r.read_event_id  AS event_id,
            r.read_time      AS event_time,
            'CredentialDiscoveryFire' AS event_name,
            r.reader_arn                AS caller_arn,
            u.use_event_id              AS correlated_use_id,
            u.access_key,
            r.surface,
            r.surface_id
        FROM reads r
        JOIN key_uses u
          ON u.use_time BETWEEN r.read_time AND r.read_time + INTERVAL 60 MINUTE
         AND u.use_ip = r.reader_ip
         AND u.user_arn != r.reader_arn

        UNION ALL

        SELECT
            u.use_event_id   AS event_id,
            u.use_time       AS event_time,
            'CredentialUseFire' AS event_name,
            u.user_arn                  AS caller_arn,
            r.read_event_id             AS correlated_use_id,
            u.access_key,
            r.surface,
            r.surface_id
        FROM reads r
        JOIN key_uses u
          ON u.use_time BETWEEN r.read_time AND r.read_time + INTERVAL 60 MINUTE
         AND u.use_ip = r.reader_ip
         AND u.user_arn != r.reader_arn
    """,

    "05": f"""
        WITH hop1 AS (
            SELECT
                eventID::VARCHAR                                                  AS h1_id,
                eventTime                                                         AS h1_time,
                userIdentity.arn                                                  AS starting_principal,
                json_extract_string(requestParameters['roleArn'], '$')            AS h1_target_role,
                'arn:aws:sts::{ACCOUNT_ID}:assumed-role/' ||
                    regexp_extract(json_extract_string(requestParameters['roleArn'], '$'), 'role/(.+)$', 1) || '/' ||
                    json_extract_string(requestParameters['roleSessionName'], '$') AS h1_assumed_arn
            FROM ct
            WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
              AND eventName = 'AssumeRole'
              AND userIdentity.type IN ('IAMUser','Root','FederatedUser')
        ),
        hop2 AS (
            SELECT
                eventID::VARCHAR                                                  AS h2_id,
                eventTime                                                         AS h2_time,
                userIdentity.arn                                                  AS h2_caller_arn,
                json_extract_string(requestParameters['roleArn'], '$')            AS h2_target_role
            FROM ct
            WHERE eventTime BETWEEN {EVAL_START} AND {EVAL_NOW}
              AND eventName = 'AssumeRole'
              AND userIdentity.type = 'AssumedRole'
        )
        SELECT
            h1.h1_id            AS event_id,
            h1.h1_time          AS event_time,
            'AssumeRoleChainFire' AS event_name,
            h1.starting_principal AS caller_arn,
            h1.h1_target_role,
            h2.h2_target_role,
            h2.h2_id            AS hop2_event_id
        FROM hop1 h1
        JOIN hop2 h2
          ON h2.h2_caller_arn = h1.h1_assumed_arn
         AND h2.h2_time BETWEEN h1.h1_time AND h1.h1_time + INTERVAL 15 MINUTE

        UNION ALL

        SELECT
            h2.h2_id            AS event_id,
            h2.h2_time          AS event_time,
            'AssumeRoleChainFire' AS event_name,
            h1.starting_principal AS caller_arn,
            h1.h1_target_role,
            h2.h2_target_role,
            h1.h1_id            AS hop2_event_id
        FROM hop1 h1
        JOIN hop2 h2
          ON h2.h2_caller_arn = h1.h1_assumed_arn
         AND h2.h2_time BETWEEN h1.h1_time AND h1.h1_time + INTERVAL 15 MINUTE
    """,
}


def score_primitive(
    con: duckdb.DuckDBPyConnection,
    prim_id: str,
    sql: str,
    event_labels: Dict[str, Tuple[str, str]],
    attack_events: Dict[str, set],
    attack_starts: Dict[str, datetime],
) -> Dict[str, Any]:

    fires = con.execute(sql).fetchall()
    fired_ids: set = set()
    fired_id_time: Dict[str, datetime] = {}
    for row in fires:
        eid = row[0]
        etime = row[1]
        fired_ids.add(eid)
        if eid not in fired_id_time or etime < fired_id_time[eid]:
            fired_id_time[eid] = etime

    tp = 0
    fp = 0
    tp_events: List[Dict[str, Any]] = []
    fp_events: List[Dict[str, Any]] = []

    for eid in fired_ids:
        if eid in event_labels:
            aid, exp_p = event_labels[eid]
            if exp_p == prim_id:
                tp += 1
                tp_events.append({"event_id": eid, "attack_id": aid})
            else:
                fp += 1
                fp_events.append({"event_id": eid, "attack_id": aid, "cross_primitive": True})
        else:
            fp += 1
            fp_events.append({"event_id": eid, "attack_id": None})

    expected_events = {eid for eid, (aid, exp_p) in event_labels.items() if exp_p == prim_id}
    fn_events = expected_events - fired_ids
    fn = len(fn_events)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2*precision*recall / (precision+recall) if (precision+recall) > 0 else 0.0

    mttd_per_attack: Dict[str, Any] = {}
    for aid in COVERAGE[prim_id]:
        attack_evt_ids = attack_events.get(aid, set())
        first_fire = None
        for eid in attack_evt_ids:
            if eid in fired_id_time:
                t = fired_id_time[eid]
                if first_fire is None or t < first_fire:
                    first_fire = t
        if first_fire is not None:
            start = attack_starts[aid]
            mttd_per_attack[aid] = (first_fire - start).total_seconds()
        else:
            mttd_per_attack[aid] = None

    valid_mttds = [v for v in mttd_per_attack.values() if v is not None]
    mttd_mean = sum(valid_mttds) / len(valid_mttds) if valid_mttds else None

    # Attack-level recall: did the primitive fire AT LEAST ONCE on each covered path?
    attacks_detected = sum(1 for aid in COVERAGE[prim_id]
                           if any(eid in fired_id_time for eid in attack_events.get(aid, set())))
    attack_recall = attacks_detected / len(COVERAGE[prim_id]) if COVERAGE[prim_id] else 0.0

    return {
        "primitive":     prim_id,
        "covered_paths": COVERAGE[prim_id],
        "total_fires":   len(fired_ids),
        "tp":            tp,
        "fp":            fp,
        "fn":            fn,
        "precision":     precision,
        "event_recall":  recall,
        "f1":            f1,
        "attacks_detected":       attacks_detected,
        "attacks_covered":        len(COVERAGE[prim_id]),
        "attack_level_recall":    attack_recall,
        "mttd_per_attack":        mttd_per_attack,
        "mttd_mean_sec":          mttd_mean,
        "tp_events":     tp_events[:5],
        "fp_events":     fp_events[:5],
        "fn_events":     list(fn_events)[:5],
    }


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--corpora-dir", type=Path, default=Path("corpora"))
    p.add_argument("--results-dir", type=Path, default=Path("results"))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    args.results_dir.mkdir(parents=True, exist_ok=True)

    baseline = args.corpora_dir / "baseline_reference.jsonl"
    positive = args.corpora_dir / "positive_corpus.jsonl"
    for p in (baseline, positive):
        if not p.exists():
            print(f"ERROR: {p} not found", file=sys.stderr)
            return 2

    con = duckdb.connect()
    con.execute(f"""
        CREATE VIEW ct AS
        SELECT * FROM read_json_auto(
            ['{baseline}', '{positive}'],
            format='newline_delimited',
            union_by_name=true,
            sample_size=-1
        );
    """)

    total_ct = con.execute("SELECT COUNT(*) FROM ct").fetchone()[0]
    total_attacks = con.execute("SELECT COUNT(pathtriage.attack_id) FROM ct").fetchone()[0]
    print(f"Loaded {total_ct:,} events ({total_attacks} labelled attack events)", file=sys.stderr)

    pos_rows = con.execute("""
        SELECT eventID::VARCHAR, pathtriage.attack_id, pathtriage.expected_primitive,
               pathtriage.step, eventTime
        FROM ct
        WHERE pathtriage.attack_id IS NOT NULL
        ORDER BY eventTime
    """).fetchall()

    event_labels:  Dict[str, Tuple[str, str]]     = {}
    attack_events: Dict[str, set]                  = {}
    attack_starts: Dict[str, datetime]             = {}
    for eid, aid, exp_p, step, et in pos_rows:
        event_labels[eid] = (aid, exp_p)
        attack_events.setdefault(aid, set()).add(eid)
        if aid not in attack_starts or et < attack_starts[aid]:
            attack_starts[aid] = et

    print(f"Positive corpus: {len(pos_rows)} events, {len(attack_starts)} attack paths", file=sys.stderr)

    all_results: Dict[str, Any] = {}
    for prim_id in sorted(QUERIES):
        print(f"\n--- Primitive {prim_id} ---", file=sys.stderr)
        try:
            result = score_primitive(
                con, prim_id, QUERIES[prim_id],
                event_labels, attack_events, attack_starts,
            )
        except Exception as exc:
            print(f"  ERROR: {exc}", file=sys.stderr)
            all_results[prim_id] = {"error": str(exc)}
            continue

        all_results[prim_id] = result

        print(f"  Covered paths: {result['covered_paths']}", file=sys.stderr)
        print(f"  Fires: {result['total_fires']} | TP={result['tp']} FP={result['fp']} FN={result['fn']}", file=sys.stderr)
        print(f"  Precision={result['precision']:.3f} EventRecall={result['event_recall']:.3f} AttackRecall={result['attack_level_recall']:.3f} F1={result['f1']:.3f}", file=sys.stderr)
        if result['mttd_mean_sec'] is not None:
            print(f"  MTTD mean: {result['mttd_mean_sec']:.1f} s", file=sys.stderr)
        for aid, mttd in result['mttd_per_attack'].items():
            marker = f"{mttd:.1f}s" if mttd is not None else "NO_FIRE"
            print(f"    {aid} -> {marker}", file=sys.stderr)

    valid = [r for r in all_results.values() if "error" not in r]
    if valid:
        macro_precision     = sum(r["precision"] for r in valid) / len(valid)
        macro_event_recall  = sum(r["event_recall"] for r in valid) / len(valid)
        macro_attack_recall = sum(r["attack_level_recall"] for r in valid) / len(valid)
        macro_f1            = sum(r["f1"]        for r in valid) / len(valid)
        mttds               = [r["mttd_mean_sec"] for r in valid if r["mttd_mean_sec"] is not None]
        macro_mttd          = sum(mttds)/len(mttds) if mttds else None
        total_paths_detected = sum(r["attacks_detected"] for r in valid)
        total_paths_covered  = sum(r["attacks_covered"] for r in valid)
    else:
        macro_precision = macro_event_recall = macro_attack_recall = macro_f1 = 0.0
        macro_mttd = None
        total_paths_detected = total_paths_covered = 0

    aggregate = {
        "corpus": {
            "baseline_events": total_ct - total_attacks,
            "attack_events":   total_attacks,
            "eval_window":     [str(EVAL_START), str(EVAL_NOW)],
        },
        "per_primitive": all_results,
        "aggregate": {
            "macro_precision":     macro_precision,
            "macro_event_recall":  macro_event_recall,
            "macro_attack_recall": macro_attack_recall,
            "macro_f1":            macro_f1,
            "macro_mttd_sec":      macro_mttd,
            "paths_detected":      total_paths_detected,
            "paths_covered":       total_paths_covered,
        },
        "coverage_gate": {
            "all_precision_ge_0.95":  all(r["precision"] >= 0.95 for r in valid),
            "all_attack_recall_1.0":  all(r["attack_level_recall"] >= 1.0 for r in valid),
            "median_mttd_le_60":      (macro_mttd is not None and macro_mttd <= 60),
        },
    }

    out_path = args.results_dir / "primitive_evaluation.json"
    with open(out_path, "w") as fh:
        json.dump(aggregate, fh, indent=2, default=str)
    print(f"\nWrote {out_path}", file=sys.stderr)

    print("\n=== Aggregate ===", file=sys.stderr)
    print(f"  Macro Precision:      {macro_precision:.3f}", file=sys.stderr)
    print(f"  Macro Event Recall:   {macro_event_recall:.3f}", file=sys.stderr)
    print(f"  Macro Attack Recall:  {macro_attack_recall:.3f}", file=sys.stderr)
    print(f"  Paths detected:       {total_paths_detected}/{total_paths_covered}", file=sys.stderr)
    print(f"  Macro F1:             {macro_f1:.3f}", file=sys.stderr)
    if macro_mttd is not None:
        print(f"  Macro MTTD:           {macro_mttd:.1f} s", file=sys.stderr)
    print(f"  Precision gate >=0.95: {aggregate['coverage_gate']['all_precision_ge_0.95']}", file=sys.stderr)
    print(f"  Attack recall gate 1.0: {aggregate['coverage_gate']['all_attack_recall_1.0']}", file=sys.stderr)
    print(f"  MTTD gate <=60s:       {aggregate['coverage_gate']['median_mttd_le_60']}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
