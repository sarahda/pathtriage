"""PathTriage CLI.

W2:  `pathtriage scan --provider aws --profile <p>`     enumerate + build graph
W5:  `pathtriage discover --provider aws --profile <p>` enumerate attack paths
W5:  `pathtriage rank --provider aws --profile <p>`     score paths under rubric v1
"""
from __future__ import annotations

import argparse
import sys

from pathtriage import __version__


def cmd_scan(args: argparse.Namespace) -> int:
    if args.provider != "aws":
        print(
    "[!] Azure enumeration is not implemented in this release.\n"
    "    The eight Azure attack paths are documented under attacks/Z*/ "
    "with verified execution logs;\n"
    "    graph integration is future work (see README).",
    file=sys.stderr,
)
        return 2
    from pathtriage.enumerators.aws import AwsEnumerator
    from pathtriage.graph.builder import build_graph, summarise

    print(f"[*] enumerating AWS IAM (profile={args.profile}, region={args.region})")
    inventory = AwsEnumerator(profile=args.profile, region=args.region).enumerate()
    if inventory.is_empty():
        print("[-] no principals found -- check credentials/permissions", file=sys.stderr)
        return 1
    graph = build_graph(inventory)
    print(f"[+] {summarise(graph)}")
    print("[*] principals:")
    for entity in (*inventory.users, *inventory.roles):
        n = len(entity.attached_policy_arns) + len(entity.inline_policy_names)
        print(f"    - [{entity.kind}] {entity.name} ({n} policies)")
    if args.output:
        nx_write(graph, args.output)
        print(f"[+] graph written to {args.output}")
    return 0


def _load_inventory(args: argparse.Namespace):
    """Load inventory from fixture JSON or via real AWS enumeration."""
    if getattr(args, "fixture", None):
        from pathtriage.enumerators.fixture import load_fixture
        print(f"[*] loading inventory from fixture: {args.fixture}")
        return load_fixture(args.fixture)
    if args.provider != "aws":
        print(
    "[!] Azure enumeration is not implemented in this release.\n"
    "    The eight Azure attack paths are documented under attacks/Z*/ "
    "with verified execution logs;\n"
    "    graph integration is future work (see README).",
    file=sys.stderr,
)
        return None
    from pathtriage.enumerators.aws import AwsEnumerator
    print(f"[*] enumerating AWS IAM (profile={args.profile}, region={args.region})")
    return AwsEnumerator(profile=args.profile, region=args.region).enumerate()


def cmd_discover(args: argparse.Namespace) -> int:
    from pathtriage.graph.builder import build_graph
    from pathtriage.discovery.bfs import discover_paths

    inventory = _load_inventory(args)
    if inventory is None:
        return 2
    if inventory.is_empty():
        print("[-] no principals found", file=sys.stderr)
        return 1
    graph = build_graph(inventory)
    print("[*] discovering paths from user nodes...")
    paths = discover_paths(graph)
    print(f"[+] {len(paths)} paths discovered")

    display = paths if not args.limit else paths[:args.limit]
    for i, path in enumerate(display, 1):
        src = graph.nodes[path.source].get("label", path.source)
        tgt = graph.nodes[path.target].get("label", path.target)
        edge_summary = " -> ".join(path.edge_types) if path.edges else "(direct)"
        print(f"  {i:3d}. [{path.hop_count} hops] {src} -> {tgt}  ({edge_summary})")

    if args.output:
        _write_paths_json(paths, graph, args.output)
        print(f"[+] {len(paths)} paths written to {args.output}")
    return 0


def cmd_rank(args: argparse.Namespace) -> int:
    from pathtriage.graph.builder import build_graph
    from pathtriage.discovery.bfs import discover_paths
    from pathtriage.scoring.rubric import rank_paths

    inventory = _load_inventory(args)
    if inventory is None:
        return 2
    if inventory.is_empty():
        print("[-] no principals found", file=sys.stderr)
        return 1
    graph = build_graph(inventory)
    paths = discover_paths(graph)
    scored = rank_paths(paths, graph)

    print(f"[+] {len(scored)} paths scored under rubric v1 (weights 0.30/0.20/0.30/0.20)")
    print("[*] ranked most-to-least exploitable:")
    display = scored if not args.limit else scored[:args.limit]
    for i, sp in enumerate(display, 1):
        src = graph.nodes[sp.path.source].get("label", sp.path.source)
        tgt = graph.nodes[sp.path.target].get("label", sp.path.target)
        print(
            f"  {i:3d}. score={sp.score:.2f}  "
            f"d_edge={sp.d_edge} h={sp.h} delta_p={sp.delta_p} d_det={sp.d_det}"
        )
        print(f"       {src} -> {tgt}")

    if args.output:
        _write_scored_json(scored, graph, args.output)
        print(f"[+] {len(scored)} scored paths written to {args.output}")
    return 0


def cmd_detail(args: argparse.Namespace) -> int:
    """Show edge-by-edge detail for a single ranked path."""
    from pathtriage.graph.builder import build_graph
    from pathtriage.discovery.bfs import discover_paths
    from pathtriage.scoring.rubric import rank_paths

    inventory = _load_inventory(args)
    if inventory is None:
        return 2
    if inventory.is_empty():
        print("[-] no principals found", file=sys.stderr)
        return 1
    graph = build_graph(inventory)
    paths = discover_paths(graph)
    scored = rank_paths(paths, graph)

    if args.rank < 1 or args.rank > len(scored):
        print(f"[-] rank {args.rank} out of range (1..{len(scored)})", file=sys.stderr)
        return 1
    sp = scored[args.rank - 1]

    print(f"[*] path #{args.rank} of {len(scored)}  (score={sp.score:.2f})")
    print(f"    source  : {graph.nodes[sp.path.source].get('label', sp.path.source)}")
    print(f"    target  : {graph.nodes[sp.path.target].get('label', sp.path.target)}")
    print(f"    hops    : {sp.path.hop_count}")
    print(f"    edges   :")
    for i, (a, b, rel) in enumerate(sp.path.edges, 1):
        a_lbl = graph.nodes[a].get("label", a)
        b_lbl = graph.nodes[b].get("label", b)
        print(f"      {i}. [{rel:15s}] {a_lbl}  ->  {b_lbl}")
    print(f"    rubric  :")
    print(f"      d_edge  = {sp.d_edge}  (per-edge difficulty)")
    print(f"      h       = {sp.h}       (hop count)")
    print(f"      delta_p = {sp.delta_p} (privilege delta)")
    print(f"      d_det   = {sp.d_det}   (detection difficulty)")
    return 0


def _write_paths_json(paths, graph, output_path: str) -> None:
    import json
    data = [_serialise_path(p, graph) for p in paths]
    with open(output_path, "w") as f:
        json.dump({"schema": "pathtriage.paths.v1", "paths": data}, f, indent=2)


def _write_scored_json(scored, graph, output_path: str) -> None:
    import json
    data = []
    for sp in scored:
        entry = _serialise_path(sp.path, graph)
        entry["score"] = sp.score
        entry["rubric"] = {
            "d_edge": sp.d_edge, "h": sp.h,
            "delta_p": sp.delta_p, "d_det": sp.d_det,
        }
        data.append(entry)
    with open(output_path, "w") as f:
        json.dump({"schema": "pathtriage.scored_paths.v1", "paths": data}, f, indent=2)


def _serialise_path(path, graph) -> dict:
    return {
        "source": path.source,
        "source_label": graph.nodes[path.source].get("label", path.source),
        "target": path.target,
        "target_label": graph.nodes[path.target].get("label", path.target),
        "hop_count": path.hop_count,
        "edges": [
            {"from": a, "to": b, "rel": rel}
            for (a, b, rel) in path.edges
        ],
    }


def nx_write(graph, path: str) -> None:
    import networkx as nx
    nx.write_graphml(graph, path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pathtriage", description="IAM attack-path discovery")
    parser.add_argument("--version", action="version", version=f"pathtriage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="enumerate a provider and build the attack graph")
    scan.add_argument("--provider", choices=["aws", "azure"], required=True)
    scan.add_argument("--profile", default=None, help="named credentials profile")
    scan.add_argument("--region", default="ap-southeast-2")
    scan.add_argument("--output", default=None, help="write graph as GraphML to this path")
    scan.set_defaults(func=cmd_scan)

    discover = sub.add_parser("discover", help="enumerate attack paths from the IAM graph")
    discover.add_argument("--provider", choices=["aws", "azure"], default="aws")
    discover.add_argument("--profile", default=None, help="named credentials profile")
    discover.add_argument("--region", default="ap-southeast-2")
    discover.add_argument("--fixture", default=None, help="load inventory from JSON fixture (offline mode)")
    discover.add_argument("--output", default=None, help="write paths as JSON to this path")
    discover.add_argument("--limit", type=int, default=0, help="show only top-N paths (0 = all)")
    discover.set_defaults(func=cmd_discover)

    rank = sub.add_parser("rank", help="score discovered paths under the rubric")
    rank.add_argument("--provider", choices=["aws", "azure"], default="aws")
    rank.add_argument("--profile", default=None, help="named credentials profile")
    rank.add_argument("--region", default="ap-southeast-2")
    rank.add_argument("--fixture", default=None, help="load inventory from JSON fixture (offline mode)")
    rank.add_argument("--output", default=None, help="write scored paths as JSON to this path")
    rank.add_argument("--limit", type=int, default=0, help="show only top-N paths (0 = all)")
    rank.set_defaults(func=cmd_rank)

    detail = sub.add_parser("detail", help="deep-dive into a single ranked path")
    detail.add_argument("--provider", choices=["aws", "azure"], default="aws")
    detail.add_argument("--profile", default=None, help="named credentials profile")
    detail.add_argument("--region", default="ap-southeast-2")
    detail.add_argument("--fixture", default=None, help="load inventory from JSON fixture (offline mode)")
    detail.add_argument("--rank", type=int, default=1, help="rank of the path to inspect (1-indexed)")
    detail.set_defaults(func=cmd_detail)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
