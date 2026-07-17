"""Tests for rubric v1 scoring."""
from __future__ import annotations

import networkx as nx

from pathtriage.discovery.bfs import AttackPath
from pathtriage.scoring.rubric import (
    W_DELTA, W_DET, W_EDGE, W_HOP,
    rank_paths, score_path,
)


def _admin_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("u", kind="user",   label="attacker")
    g.add_node("r", kind="role",   label="admin-role")
    g.add_node("pa", kind="policy", label="AdministratorAccess")
    g.add_node("pr", kind="policy", label="AmazonS3ReadOnlyAccess")
    return g


def test_weights_sum_to_one():
    assert abs((W_EDGE + W_HOP + W_DELTA + W_DET) - 1.0) < 1e-9


def test_admin_path_scores_higher_than_readonly():
    g = _admin_graph()
    admin = AttackPath("u", "pa", edges=[("u", "pa", "HAS_POLICY")])
    ro    = AttackPath("u", "pr", edges=[("u", "pr", "HAS_POLICY")])
    s_admin = score_path(admin, g)
    s_ro    = score_path(ro, g)
    assert s_admin.score > s_ro.score
    assert s_admin.delta_p == 5    # AdministratorAccess -> max
    assert s_ro.delta_p == 3       # not admin-keyword


def test_shorter_path_scores_higher_ceteris_paribus():
    g = _admin_graph()
    g.add_node("r2", kind="role", label="intermediate")
    short = AttackPath("u", "pa", edges=[("u", "pa", "HAS_POLICY")])
    long_ = AttackPath("u", "pa", edges=[
        ("u", "r2", "CAN_ASSUME"),
        ("r2", "pa", "HAS_POLICY"),
    ])
    s_short = score_path(short, g)
    s_long  = score_path(long_, g)
    assert s_short.score >= s_long.score


def test_rank_paths_returns_descending_order():
    g = _admin_graph()
    paths = [
        AttackPath("u", "pr", edges=[("u", "pr", "HAS_POLICY")]),
        AttackPath("u", "pa", edges=[("u", "pa", "HAS_POLICY")]),
    ]
    scored = rank_paths(paths, g)
    assert scored[0].score >= scored[1].score
    assert scored[0].path.target == "pa"
