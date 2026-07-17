"""Tests for path discovery over the IAM graph."""
from __future__ import annotations

import networkx as nx

from pathtriage.discovery.bfs import AttackPath, discover_paths


def _tiny_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("user:alice",   kind="user",   label="alice")
    g.add_node("role:admin",   kind="role",   label="admin-role")
    g.add_node("pol:admin",    kind="policy", label="AdministratorAccess")
    g.add_node("pol:readonly", kind="policy", label="AmazonS3ReadOnlyAccess")
    g.add_edge("user:alice", "role:admin",   rel="CAN_ASSUME")
    g.add_edge("role:admin", "pol:admin",    rel="HAS_POLICY")
    g.add_edge("user:alice", "pol:readonly", rel="HAS_POLICY")
    return g


def test_discover_reaches_direct_and_transitive_targets():
    g = _tiny_graph()
    paths = discover_paths(g)

    targets = {p.target for p in paths}
    assert "role:admin" in targets       # direct via CAN_ASSUME
    assert "pol:admin" in targets        # transitive (user -> role -> policy)
    assert "pol:readonly" in targets     # direct via HAS_POLICY


def test_discover_captures_hop_counts():
    g = _tiny_graph()
    paths = discover_paths(g)
    hops = {p.target: p.hop_count for p in paths}
    assert hops["role:admin"]   == 1
    assert hops["pol:admin"]    == 2
    assert hops["pol:readonly"] == 1


def test_discover_ignores_non_user_starts_by_default():
    g = _tiny_graph()
    g.add_node("role:orphan", kind="role", label="orphan")
    g.add_edge("role:orphan", "pol:admin", rel="HAS_POLICY")
    paths = discover_paths(g)
    sources = {p.source for p in paths}
    assert sources == {"user:alice"}


def test_attack_path_edge_types_property():
    p = AttackPath(
        source="u",
        target="p",
        edges=[("u", "r", "CAN_ASSUME"), ("r", "p", "HAS_POLICY")],
    )
    assert p.edge_types == ["CAN_ASSUME", "HAS_POLICY"]
    assert p.hop_count == 2
