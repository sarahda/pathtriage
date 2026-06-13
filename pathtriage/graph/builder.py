"""Build a NetworkX DiGraph over the enumerated IAM entities.

Nodes:  one per user, role, and customer-managed policy.
Edges:  HAS_POLICY (principal -> policy) for attached managed policies.

Later weeks add the edges that actually express attack reachability
(PASS_ROLE, CAN_ASSUME, ESCALATES_VIA, etc.). For W2 the deliverable is just a
non-empty graph that `scan` can summarise.
"""
from __future__ import annotations

import networkx as nx

from pathtriage.enumerators.aws import IamInventory


def build_graph(inv: IamInventory) -> nx.DiGraph:
    g = nx.DiGraph()

    for policy_arn, policy_name in inv.policies.items():
        g.add_node(policy_arn, label=policy_name, kind="policy")

    for entity in (*inv.users, *inv.roles):
        g.add_node(entity.arn, label=entity.name, kind=entity.kind)
        for policy_arn in entity.attached_policy_arns:
            # ensure the target node exists even for AWS-managed policies
            if policy_arn not in g:
                g.add_node(policy_arn, label=policy_arn.split("/")[-1], kind="policy")
            g.add_edge(entity.arn, policy_arn, rel="HAS_POLICY")

    return g


def summarise(g: nx.DiGraph) -> str:
    kinds: dict[str, int] = {}
    for _, data in g.nodes(data=True):
        kinds[data.get("kind", "?")] = kinds.get(data.get("kind", "?"), 0) + 1
    parts = ", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))
    return (
        f"graph: {g.number_of_nodes()} nodes ({parts}), "
        f"{g.number_of_edges()} edges"
    )
