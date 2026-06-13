"""PathTriage CLI.

W2 target:  `pathtriage scan --provider aws --profile <p>` produces a non-empty
graph and prints a summary.

    pathtriage scan --provider aws --profile lowpriv
"""
from __future__ import annotations

import argparse
import sys

from pathtriage import __version__


def cmd_scan(args: argparse.Namespace) -> int:
    if args.provider != "aws":
        print(f"provider '{args.provider}' not implemented yet (W7: azure)", file=sys.stderr)
        return 2

    # imported lazily so `--help` works without boto3/networkx installed
    from pathtriage.enumerators.aws import AwsEnumerator
    from pathtriage.graph.builder import build_graph, summarise

    print(f"[*] enumerating AWS IAM (profile={args.profile}, region={args.region})")
    inventory = AwsEnumerator(profile=args.profile, region=args.region).enumerate()

    if inventory.is_empty():
        print("[-] no principals found — check credentials/permissions", file=sys.stderr)
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
