"""Path discovery over the IAM attack graph (W5).

Walks the graph from user nodes outward via HAS_POLICY edges, enumerating
reachable policies. Each resulting path is a sequence of (source, target,
edge_rel) tuples.

W5 scope: traverse HAS_POLICY edges only -- that's all the current graph
exposes. Attack-primitive edges (CAN_ASSUME, CAN_PASS_ROLE, CAN_MODIFY_POLICY,
CAN_ATTACH_POLICY) are added by the enumerator's edge inference step in W6+;
the same BFS implementation walks them transparently once present.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx


@dataclass
class AttackPath:
    """A path through the IAM graph: ordered ARNs + the edges between them."""

    source: str  # ARN of the starting principal
    target: str  # ARN of the terminal node (usually a policy)
    edges: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def hop_count(self) -> int:
        return len(self.edges)

    @property
    def edge_types(self) -> list[str]:
        return [rel for _, _, rel in self.edges]

    def __repr__(self) -> str:
        return f"AttackPath({self.source} -> {self.target}, {self.hop_count} hops)"


def discover_paths(
    graph: nx.DiGraph, start_kinds: tuple[str, ...] = ("user",)
) -> list[AttackPath]:
    """Enumerate paths from start nodes (default: users) to reachable nodes.

    W5 implementation: simple BFS over all outgoing edges from each start node.
    Each discovered terminal (typically a policy ARN) yields one AttackPath.
    Multiple paths to the same target via different intermediaries are kept
    separately -- important for later when intermediate role nodes appear.
    """
    paths: list[AttackPath] = []

    starts = [
        node for node, data in graph.nodes(data=True)
        if data.get("kind") in start_kinds
    ]

    for start in starts:
        # BFS: each queue entry is (current_node, edges_taken_so_far)
        queue: list[tuple[str, list[tuple[str, str, str]]]] = [(start, [])]
        visited_targets: set[str] = set()

        while queue:
            current, edges_so_far = queue.pop(0)

            # any node reached from start (other than start itself) is a target
            if current != start and current not in visited_targets:
                visited_targets.add(current)
                paths.append(AttackPath(
                    source=start,
                    target=current,
                    edges=list(edges_so_far),
                ))

            for _, neighbour, edge_data in graph.out_edges(current, data=True):
                if neighbour in visited_targets or neighbour == start:
                    continue
                new_edges = edges_so_far + [
                    (current, neighbour, edge_data.get("rel", "?"))
                ]
                queue.append((neighbour, new_edges))

    return paths
