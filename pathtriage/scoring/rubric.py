"""Exploitability rubric v1 -- score discovered attack paths.

The rubric combines four ordinal inputs into a single 1.0-5.0 score:

  Score = 0.30 * (6 - d_edge) + 0.20 * (6 - h) + 0.30 * delta_p + 0.20 * d_det

  d_edge:  per-edge difficulty (1=trivial, 5=specialist)
  h:       hop count (1=single call, 5=multi-hop chain)
  delta_p: privilege delta (1=lateral, 5=AdministratorAccess)
  d_det:   detection difficulty (1=loud, 5=silent)

W5 implementation: heuristic estimation from edge types and target node
attributes. Weights freeze in W6 against the supervisor's independent ranking;
the structure here is stable across recalibrations.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from pathtriage.discovery.bfs import AttackPath


# v1 weights -- frozen after W6 calibration
W_EDGE = 0.30
W_HOP = 0.20
W_DELTA = 0.30
W_DET = 0.20


# heuristic mapping: edge type -> per-edge difficulty (1-5)
EDGE_DIFFICULTY = {
    "HAS_POLICY": 1,
    "CAN_ASSUME": 2,
    "CAN_PASS_ROLE": 2,
    "CAN_MODIFY_POLICY": 1,
    "CAN_ATTACH_POLICY": 1,
}


ADMIN_POLICY_KEYWORDS = (
    "Administrator", "FullAccess", "PowerUser", "Admin",
)


@dataclass
class ScoredPath:
    path: AttackPath
    d_edge: int
    h: int
    delta_p: int
    d_det: int
    score: float


def _per_edge_difficulty(path: AttackPath) -> int:
    if not path.edges:
        return 1
    diffs = [EDGE_DIFFICULTY.get(rel, 3) for _, _, rel in path.edges]
    return max(1, min(5, round(sum(diffs) / len(diffs))))


def _hop_count(path: AttackPath) -> int:
    return max(1, min(5, path.hop_count))


def _privilege_delta(path: AttackPath, graph: nx.DiGraph) -> int:
    target_data = graph.nodes.get(path.target, {})
    if target_data.get("kind") != "policy":
        return 1
    label = target_data.get("label", "")
    if any(keyword in label for keyword in ADMIN_POLICY_KEYWORDS):
        return 5
    return 3


def _detection_difficulty(path: AttackPath) -> int:
    if not path.edges:
        return 3
    edge_types = path.edge_types
    if any(rel in ("CAN_MODIFY_POLICY", "CAN_ATTACH_POLICY") for rel in edge_types):
        return 1  # loud iam:* CloudTrail events
    if "CAN_ASSUME" in edge_types:
        return 4  # blends with legitimate role hopping
    return 3


def score_path(path: AttackPath, graph: nx.DiGraph) -> ScoredPath:
    d_edge = _per_edge_difficulty(path)
    h = _hop_count(path)
    delta_p = _privilege_delta(path, graph)
    d_det = _detection_difficulty(path)

    # d_edge and h reversed so that easy + short -> high score
    score = (
        W_EDGE * (6 - d_edge)
        + W_HOP * (6 - h)
        + W_DELTA * delta_p
        + W_DET * d_det
    )

    return ScoredPath(
        path=path,
        d_edge=d_edge,
        h=h,
        delta_p=delta_p,
        d_det=d_det,
        score=round(score, 2),
    )


def rank_paths(
    paths: list[AttackPath], graph: nx.DiGraph
) -> list[ScoredPath]:
    """Score every path and return them sorted most-to-least exploitable."""
    scored = [score_path(p, graph) for p in paths]
    return sorted(scored, key=lambda sp: sp.score, reverse=True)
