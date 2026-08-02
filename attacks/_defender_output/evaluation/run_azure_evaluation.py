#!/usr/bin/env python3
"""
PathTriage — Azure detection evaluation harness.

Mirrors run_evaluation.py (AWS) for the Azure side. Scores the five detection
primitives against a corpus of Azure Activity Log and Entra sign-in records.

On the queries
--------------
The primitives are authored in KQL, under primitives/*/azure_query.kql, which
is the language a defender would deploy in Log Analytics or Sentinel. DuckDB
does not execute KQL, so the queries below are SQL translations that apply the
same conditions to the same fields. This is the same arrangement as the AWS
side, where the committed CloudTrail Lake SQL is translated for DuckDB —
Section 9.2 of the Technical Report records why.

A translation is not the original. What this harness measures is whether the
detection logic separates the attack events from the benign ones; it does not
establish that the KQL executes correctly against a live Log Analytics
workspace, which has not been tested.

Usage
-----
    python3 run_azure_evaluation.py \\
        --corpora-dir corpora --results-dir results
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

try:
    import duckdb
except ImportError:
    sys.exit("duckdb not installed — pip install 'duckdb>=0.10'")


COVERAGE: Dict[str, List[str]] = {
    "01": ["Z1", "Z8"],
    "02": ["Z3"],
    "03": ["Z4"],
    "04": ["Z2", "Z5", "Z6"],
    "05": ["Z7"],
}

PRIMITIVE_NAMES = {
    "01": "IMDS / managed-identity extraction",
    "02": "IAM modification (assign)",
    "03": "IAM modification (mutate)",
    "04": "Credential discovery",
    "05": "Trust topology",
}

# Addresses managed identities legitimately use, per the baseline generator.
VNET_EGRESS = "('20.53.100.10','20.53.100.11')"

PERSIST_GATE_SEC  = 600     # primitive 03 — mutation must be exercised within
CORRELATE_SEC     = 1800    # primitive 04 — read to sign-in window
CASCADE_GATE_SEC  = 900     # primitive 05 — grant to use window


QUERIES: Dict[str, str] = {

    # -- 01 --------------------------------------------------------------
    # Managed-identity operation from an address outside both the VNet
    # egress set and the identity's own history.
    #
    # Operations owned by primitives 02-04 are excluded. Primitive 01 is
    # about a stolen token being *used*; a role write or a listKeys call by
    # the same identity is the subject of another primitive, and letting
    # every primitive fire on every attack event would make the per-primitive
    # figures meaningless.
    "01": f"""
        WITH baseline AS (
            SELECT caller, list(DISTINCT caller_ip) AS known_ips
            FROM act
            WHERE attack_id IS NULL
            GROUP BY caller
        )
        SELECT
            a.event_id, a.event_time, a.operation,
            a.caller, a.caller_ip, a.resource_id
        FROM act a
        LEFT JOIN baseline b ON a.caller = b.caller
        WHERE a.caller_type = 'ManagedIdentity'
          AND a.caller_ip NOT IN {VNET_EGRESS}
          AND (b.known_ips IS NULL OR NOT list_contains(b.known_ips, a.caller_ip))
          AND a.operation NOT IN (
              'Microsoft.Authorization/roleAssignments/write',
              'Microsoft.Authorization/roleDefinitions/write',
              'Microsoft.Storage/storageAccounts/listKeys/action',
              'Microsoft.KeyVault/vaults/secrets/read',
              'Microsoft.Web/sites/config/list/action'
          )
    """,

    # -- 02 --------------------------------------------------------------
    # Role assignment write by a principal with no such history, granting
    # to itself or to a principal that has not held a grant before.
    "02": """
        WITH admin_history AS (
            SELECT DISTINCT caller FROM act
            WHERE attack_id IS NULL
              AND operation = 'Microsoft.Authorization/roleAssignments/write'
        )
        SELECT
            a.event_id, a.event_time, a.operation,
            a.caller, a.caller_ip, a.resource_id, a.grantee_oid
        FROM act a
        WHERE a.operation = 'Microsoft.Authorization/roleAssignments/write'
          AND a.caller NOT IN (SELECT caller FROM admin_history)
          AND a.grantee_oid = a.caller_oid          -- self-grant
    """,

    # -- 03 --------------------------------------------------------------
    # Role definition write by a principal with no such history, gated on a
    # follow-on write inside the persistence window. Finding 2: an
    # over-reaching mutation is reverted server-side, so the write alone is
    # not evidence and the follow-on is what distinguishes the two arms.
    "03": f"""
        WITH definition_history AS (
            SELECT DISTINCT caller FROM act
            WHERE attack_id IS NULL
              AND operation = 'Microsoft.Authorization/roleDefinitions/write'
        ),
        mutations AS (
            SELECT event_id, event_time, caller, caller_ip, resource_id
            FROM act
            WHERE operation = 'Microsoft.Authorization/roleDefinitions/write'
              AND caller NOT IN (SELECT caller FROM definition_history)
        ),
        follow_on AS (
            SELECT event_time AS use_time, caller, operation AS use_op
            FROM act
            WHERE (operation LIKE '%/write' OR operation LIKE '%/action')
              AND operation <> 'Microsoft.Authorization/roleDefinitions/write'
        )
        SELECT DISTINCT
            m.event_id, m.event_time,
            'Microsoft.Authorization/roleDefinitions/write' AS operation,
            m.caller, m.caller_ip, m.resource_id
        FROM mutations m
        JOIN follow_on f
          ON m.caller = f.caller
         AND f.use_time > m.event_time
         AND date_diff('second', m.event_time, f.use_time) <= {PERSIST_GATE_SEC}
    """,

    # -- 04 --------------------------------------------------------------
    # Credential-bearing surface read, followed by a sign-in from a
    # principal absent from the baseline.
    "04": f"""
        WITH known_principals AS (
            SELECT DISTINCT principal FROM sig WHERE attack_id IS NULL
        ),
        reader_history AS (
            SELECT DISTINCT caller, operation FROM act
            WHERE attack_id IS NULL
        ),
        reads AS (
            SELECT a.event_id, a.event_time, a.caller, a.caller_ip,
                   a.operation, a.resource_id
            FROM act a
            WHERE a.operation IN (
                'Microsoft.KeyVault/vaults/secrets/read',
                'Microsoft.Storage/storageAccounts/listKeys/action',
                'Microsoft.Web/sites/config/list/action'
            )
              AND NOT EXISTS (
                  SELECT 1 FROM reader_history h
                  WHERE h.caller = a.caller AND h.operation = a.operation
              )
        ),
        new_signins AS (
            SELECT event_time AS signin_time, principal
            FROM sig
            WHERE principal NOT IN (SELECT principal FROM known_principals)
        )
        SELECT DISTINCT
            r.event_id, r.event_time, r.operation,
            r.caller, r.caller_ip, r.resource_id
        FROM reads r
        JOIN new_signins n
          ON n.signin_time > r.event_time
         AND date_diff('second', r.event_time, n.signin_time) <= {CORRELATE_SEC}
    """,

    # -- 05 --------------------------------------------------------------
    # Role granted to a second principal, then exercised by that principal.
    # The join is on the grantee's object id, which the Activity Log records
    # in properties.principalId. D-Z7-03: the 30-60s propagation delay is
    # part of the signature, and has no AWS analogue.
    "05": f"""
        WITH granter_history AS (
            SELECT DISTINCT caller FROM act
            WHERE attack_id IS NULL
              AND operation = 'Microsoft.Authorization/roleAssignments/write'
        ),
        grants AS (
            SELECT event_id, event_time, caller, caller_oid, caller_ip,
                   resource_id, grantee_oid
            FROM act
            WHERE operation = 'Microsoft.Authorization/roleAssignments/write'
              AND grantee_oid IS NOT NULL
              AND caller NOT IN (SELECT caller FROM granter_history)
        ),
        uses AS (
            SELECT event_time AS use_time, caller_oid AS actor_oid, caller AS actor
            FROM act
            WHERE operation LIKE '%/write'
        )
        SELECT DISTINCT
            g.event_id, g.event_time,
            'Microsoft.Authorization/roleAssignments/write' AS operation,
            g.caller, g.caller_ip, g.resource_id, g.grantee_oid
        FROM grants g
        JOIN uses u
          ON u.actor_oid = g.grantee_oid
         AND u.actor_oid <> g.caller_oid
         AND u.use_time > g.event_time
         AND date_diff('second', g.event_time, u.use_time) <= {CASCADE_GATE_SEC}
    """,
}


def load_corpora(con, corpora: Path) -> Tuple[int, int, int]:
    """Register act and sig views; return (activity, signin, attack) counts."""
    act_files = [corpora / "azure_activity_baseline.jsonl",
                 corpora / "azure_activity_positive.jsonl"]
    sig_files = [corpora / "azure_signin_baseline.jsonl",
                 corpora / "azure_signin_positive.jsonl"]
    for f in act_files + sig_files:
        if not f.exists():
            sys.exit(f"missing corpus file: {f}")

    con.execute(f"""
        CREATE OR REPLACE VIEW act AS
        SELECT
            eventDataId::VARCHAR                        AS event_id,
            time::TIMESTAMP                              AS event_time,
            operationName                               AS operation,
            caller                                      AS caller,
            json_extract_string(identity, '$.type')     AS caller_type,
            json_extract_string(identity, '$.claims.oid') AS caller_oid,
            json_extract_string(properties, '$.principalId') AS grantee_oid,
            callerIpAddress                             AS caller_ip,
            resourceId                                  AS resource_id,
            json_extract_string(pathtriage, '$.attack_id')          AS attack_id,
            json_extract_string(pathtriage, '$.expected_primitive') AS expected_primitive
        FROM read_json_auto({[str(f) for f in act_files]!r}, union_by_name=true)
    """)
    con.execute(f"""
        CREATE OR REPLACE VIEW sig AS
        SELECT
            json_extract_string(properties, '$.id')::VARCHAR AS event_id,
            time::TIMESTAMP                                   AS event_time,
            identity                                          AS principal,
            json_extract_string(properties, '$.ipAddress')    AS principal_ip,
            json_extract_string(pathtriage, '$.attack_id')          AS attack_id,
            json_extract_string(pathtriage, '$.expected_primitive') AS expected_primitive
        FROM read_json_auto({[str(f) for f in sig_files]!r}, union_by_name=true)
    """)

    n_act = con.execute("SELECT count(*) FROM act").fetchone()[0]
    n_sig = con.execute("SELECT count(*) FROM sig").fetchone()[0]
    n_atk = con.execute(
        "SELECT count(*) FROM (SELECT attack_id FROM act WHERE attack_id IS NOT NULL "
        "UNION ALL SELECT attack_id FROM sig WHERE attack_id IS NOT NULL)"
    ).fetchone()[0]
    return n_act, n_sig, n_atk


def score(con, pid: str) -> Dict[str, Any]:
    rows = con.execute(QUERIES[pid]).fetchall()
    cols = [d[0] for d in con.description]
    fired = [dict(zip(cols, r)) for r in rows]

    covered = COVERAGE[pid]

    # Detection targets are Activity Log events. Sign-in records are context
    # the queries join against, not rows they return, so they are excluded
    # from the truth set rather than counted as missed detections.
    truth = con.execute(f"""
        SELECT event_id, attack_id, event_time FROM act
        WHERE expected_primitive = '{pid}'
    """).fetchall()
    truth_ids: Set[str] = {r[0] for r in truth}

    # Attack start is the first observable of the path in either stream, not
    # the first event this primitive happens to target. Measuring from the
    # latter would report a detection latency of zero by construction.
    starts = con.execute("""
        SELECT attack_id, min(t) FROM (
            SELECT attack_id, event_time AS t FROM act WHERE attack_id IS NOT NULL
            UNION ALL
            SELECT attack_id, event_time AS t FROM sig WHERE attack_id IS NOT NULL
        ) GROUP BY attack_id
    """).fetchall()
    first_seen = {a: t for a, t in starts}

    # Map every event id to its path once, rather than per-hit
    id_to_path = dict(con.execute("""
        SELECT event_id, attack_id FROM act WHERE attack_id IS NOT NULL
        UNION ALL
        SELECT event_id, attack_id FROM sig WHERE attack_id IS NOT NULL
    """).fetchall())
    id_to_time = dict(con.execute("""
        SELECT event_id, event_time FROM act
        UNION ALL
        SELECT event_id, event_time FROM sig
    """).fetchall())

    fired_ids = {f["event_id"] for f in fired}
    tp_ids = fired_ids & truth_ids
    fp_ids = fired_ids - truth_ids
    fn_ids = truth_ids - fired_ids

    # A fire on an attack event belonging to a different path is not the same
    # error as a fire on benign traffic. The first is a correct alert with the
    # wrong attribution; the second is the one that costs an analyst their
    # afternoon. They are separated here because collapsing them into one
    # precision figure would hide which kind of mistake the primitive makes.
    cross_path_fp = {e for e in fp_ids if e in id_to_path}
    benign_fp = fp_ids - cross_path_fp

    # attack-level: a path counts as detected if any of its events fired
    detected_paths: Set[str] = {id_to_path[e] for e in tp_ids if e in id_to_path}

    # MTTD: from the path's first observable to this primitive's first hit
    mttd: Dict[str, float] = {}
    for path in detected_paths:
        hits = [id_to_time[e] for e in tp_ids
                if id_to_path.get(e) == path and e in id_to_time]
        if hits and path in first_seen:
            mttd[path] = (min(hits) - first_seen[path]).total_seconds()

    tp, fp, fn = len(tp_ids), len(fp_ids), len(fn_ids)
    n_benign_fp = len(benign_fp)
    # Precision against benign traffic: the operational question is whether
    # the primitive is safe to deploy, and a fire on another path's attack
    # event does not bear on that.
    precision = tp / (tp + n_benign_fp) if (tp + n_benign_fp) else 0.0
    precision_strict = tp / (tp + fp) if (tp + fp) else 0.0
    event_recall = tp / (tp + fn) if (tp + fn) else 0.0
    attack_recall = len(detected_paths) / len(covered) if covered else 0.0
    f1 = (2 * precision * event_recall / (precision + event_recall)
          if (precision + event_recall) else 0.0)

    return {
        "primitive": pid,
        "name": PRIMITIVE_NAMES[pid],
        "covered_paths": covered,
        "detected_paths": sorted(detected_paths),
        "fires": len(fired),
        "tp": tp, "fp": fp, "fn": fn,
        "benign_fp": n_benign_fp,
        "cross_path_fp": len(cross_path_fp),
        "cross_path_fp_paths": sorted({id_to_path[e] for e in cross_path_fp}),
        "precision": round(precision, 4),
        "precision_strict": round(precision_strict, 4),
        "event_recall": round(event_recall, 4),
        "attack_recall": round(attack_recall, 4),
        "f1": round(f1, 4),
        "mttd_per_path": {k: round(v, 1) for k, v in sorted(mttd.items())},
        "mttd_mean_sec": round(statistics.mean(mttd.values()), 1) if mttd else None,
        "fp_events": sorted(fp_ids)[:20],
        "fn_events": sorted(fn_ids)[:20],
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--corpora-dir", type=Path, default=Path("corpora"))
    p.add_argument("--results-dir", type=Path, default=Path("results"))
    a = p.parse_args()

    con = duckdb.connect()
    n_act, n_sig, n_atk = load_corpora(con, a.corpora_dir)
    print(f"Loaded {n_act:,} activity events and {n_sig:,} sign-in events "
          f"({n_atk} labelled attack events)")
    print(f"Azure paths in corpus: "
          f"{con.execute('SELECT count(DISTINCT attack_id) FROM act WHERE attack_id IS NOT NULL').fetchone()[0]}")

    results = []
    for pid in sorted(QUERIES):
        r = score(con, pid)
        results.append(r)
        print(f"\n--- Primitive {pid} — {r['name']} ---")
        print(f"  Covered paths: {r['covered_paths']}")
        print(f"  Detected:      {r['detected_paths']}")
        print(f"  Fires: {r['fires']} | TP={r['tp']} FN={r['fn']} | "
              f"FP: {r['benign_fp']} benign, {r['cross_path_fp']} cross-path"
              + (f" {r['cross_path_fp_paths']}" if r['cross_path_fp'] else ""))
        print(f"  Precision={r['precision']:.3f} EventRecall={r['event_recall']:.3f} "
              f"AttackRecall={r['attack_recall']:.3f} F1={r['f1']:.3f}")
        if r["mttd_mean_sec"] is not None:
            print(f"  MTTD mean: {r['mttd_mean_sec']} s")
            for k, v in r["mttd_per_path"].items():
                print(f"    {k} -> {v}s")

    macro_p = statistics.mean(r["precision"] for r in results)
    macro_er = statistics.mean(r["event_recall"] for r in results)
    macro_ar = statistics.mean(r["attack_recall"] for r in results)
    macro_f1 = statistics.mean(r["f1"] for r in results)
    mttds = [r["mttd_mean_sec"] for r in results if r["mttd_mean_sec"] is not None]
    macro_mttd = round(statistics.mean(mttds), 1) if mttds else None
    detected = sorted({p for r in results for p in r["detected_paths"]})
    covered = sorted({p for r in results for p in r["covered_paths"]})

    agg = {
        "macro_precision": round(macro_p, 4),
        "macro_event_recall": round(macro_er, 4),
        "macro_attack_recall": round(macro_ar, 4),
        "macro_f1": round(macro_f1, 4),
        "macro_mttd_sec": macro_mttd,
        "paths_detected": len(detected),
        "paths_covered": len(covered),
    }
    gates = {
        "all_precision_ge_0.95": all(r["precision"] >= 0.95 for r in results),
        "all_attack_recall_1.0": all(r["attack_recall"] == 1.0 for r in results),
        "median_mttd_le_60": (statistics.median(mttds) <= 60) if mttds else False,
    }

    a.results_dir.mkdir(parents=True, exist_ok=True)
    out = a.results_dir / "azure_primitive_evaluation.json"
    out.write_text(json.dumps(
        {"per_primitive": {r["primitive"]: r for r in results},
         "aggregate": agg, "coverage_gate": gates}, indent=2))
    print(f"\nWrote {out}")

    print("\n=== Aggregate ===")
    print(f"  Macro Precision:      {agg['macro_precision']:.3f}")
    print(f"  Macro Event Recall:   {agg['macro_event_recall']:.3f}")
    print(f"  Macro Attack Recall:  {agg['macro_attack_recall']:.3f}")
    print(f"  Paths detected:       {agg['paths_detected']}/{agg['paths_covered']}")
    print(f"  Macro F1:             {agg['macro_f1']:.3f}")
    print(f"  Macro MTTD:           {agg['macro_mttd_sec']} s")
    for k, v in gates.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
