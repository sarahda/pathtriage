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
        print(f"provider '{args.provider}' not implemented yet (W7: azure)", file=sys.stderr)
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


def cmd_discover(args: argparse.Namespace) -> int:
    if args.provider != "aws":
        print(f"provider '{args.provider}' not implemented yet (W7: azure)", file=sys.stderr)
        return 2
    from pathtriage.enumerators.aws import AwsEnumerator
    from pathtriage.graph.builder import build_graph
    from pathtriage.discovery.bfs import discover_paths

    print(f"[*] enumerating AWS IAM (profile={args.profile}, region={args.region})")
    inventory = AwsEnumerator(profile=args.profile, region=args.region).enumerate()
    if inventory.is_empty():
        print("[-] no principals found", file=sys.stderr)
        return 1
    graph = build_graph(inventory)
    print("[*] discovering paths from user nodes...")
    paths = discover_paths(graph)
    print(f"[+] {len(paths)} paths discovered")
    for i, path in enumerate(paths, 1):
        src = graph.nodes[path.source].get("label", path.source)
        tgt = graph.nodes[path.target].get("label", path.target)
        edge_summary = " -> ".join(path.edge_types) if path.edges else "(direct)"
        print(f"  {i:3d}. [{path.hop_count} hops] {src} -> {tgt}  ({edge_summary})")
    return 0


def cmd_rank(args: argparse.Namespace) -> int:
    if args.provider != "aws":
        print(f"provider '{args.provider}' not implemented yet (W7: azure)", file=sys.stderr)
        return 2
    from pathtriage.enumerators.aws import AwsEnumerator
    from pathtriage.graph.builder import build_graph
    from pathtriage.discovery.bfs import discover_paths
    from pathtriage.scoring.rubric import rank_paths

    print(f"[*] enumerating AWS IAM (profile={args.profile}, region={args.region})")
    inventory = AwsEnumerator(profile=args.profile, region=args.region).enumerate()
    if inventory.is_empty():
        print("[-] no principals found", file=sys.stderr)
        return 1
    graph = build_graph(inventory)
    paths = discover_paths(graph)
    scored = rank_paths(paths, graph)

    print(f"[+] {len(scored)} paths scored under rubric v1 (weights 0.30/0.20/0.30/0.20)")
    print("[*] ranked most-to-least exploitable:")
    for i, sp in enumerate(scored, 1):
        src = graph.nodes[sp.path.source].get("label", sp.path.source)
        tgt = graph.nodes[sp.path.target].get("label", sp.path.target)
        print(
            f"  {i:3d}. score={sp.score:.2f}  "
            f"d_edge={sp.d_edge} h={sp.h} delta_p={sp.delta_p} d_det={sp.d_det}"
        )
        print(f"       {src} -> {tgt}")
    return 0


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
    discover.add_argument("--provider", choices=["aws", "azure"], required=True)
    discover.add_argument("--profile", default=None, help="named credentials profile")
    discover.add_argument("--region", default="ap-southeast-2")
    discover.set_defaults(func=cmd_discover)

    rank = sub.add_parser("rank", help="score discovered paths under the rubric")
    rank.add_argument("--provider", choices=["aws", "azure"], required=True)
    rank.add_argument("--profile", default=None, help="named credentials profile")
    rank.add_argument("--region", default="ap-southeast-2")
    rank.set_defaults(func=cmd_rank)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
