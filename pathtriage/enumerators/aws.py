"""AWS IAM enumeration via boto3.

W2 scope: enumerate the principals and policies we need to seed the attack
graph — users, roles, and the customer-managed policies attached to them.
Edge inference (which permission combinations form a path) lands in later weeks;
this module just produces the raw entity inventory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import boto3


@dataclass
class IamEntity:
    """A principal (user or role) and the policies attached to it."""

    name: str
    kind: str  # "user" | "role"
    arn: str
    attached_policy_arns: list[str] = field(default_factory=list)
    inline_policy_names: list[str] = field(default_factory=list)


@dataclass
class IamInventory:
    users: list[IamEntity] = field(default_factory=list)
    roles: list[IamEntity] = field(default_factory=list)
    policies: dict[str, str] = field(default_factory=dict)  # arn -> name

    def is_empty(self) -> bool:
        return not (self.users or self.roles)


class AwsEnumerator:
    def __init__(self, profile: Optional[str] = None, region: str = "ap-southeast-2"):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = self.session.client("iam")

    def enumerate(self) -> IamInventory:
        inv = IamInventory()
        self._collect_users(inv)
        self._collect_roles(inv)
        self._collect_policies(inv)
        return inv

    def _collect_users(self, inv: IamInventory) -> None:
        for page in self.iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                inv.users.append(
                    IamEntity(
                        name=u["UserName"],
                        kind="user",
                        arn=u["Arn"],
                        attached_policy_arns=self._attached(u["UserName"], "user"),
                        inline_policy_names=self._inline(u["UserName"], "user"),
                    )
                )

    def _collect_roles(self, inv: IamInventory) -> None:
        for page in self.iam.get_paginator("list_roles").paginate():
            for r in page["Roles"]:
                # skip AWS service-linked roles to keep the graph focused
                if r["Path"].startswith("/aws-service-role/"):
                    continue
                inv.roles.append(
                    IamEntity(
                        name=r["RoleName"],
                        kind="role",
                        arn=r["Arn"],
                        attached_policy_arns=self._attached(r["RoleName"], "role"),
                        inline_policy_names=self._inline(r["RoleName"], "role"),
                    )
                )

    def _collect_policies(self, inv: IamInventory) -> None:
        for page in self.iam.get_paginator("list_policies").paginate(Scope="Local"):
            for p in page["Policies"]:
                inv.policies[p["Arn"]] = p["PolicyName"]

    def _attached(self, name: str, kind: str) -> list[str]:
        if kind == "user":
            resp = self.iam.list_attached_user_policies(UserName=name)
        else:
            resp = self.iam.list_attached_role_policies(RoleName=name)
        return [p["PolicyArn"] for p in resp["AttachedPolicies"]]

    def _inline(self, name: str, kind: str) -> list[str]:
        if kind == "user":
            return self.iam.list_user_policies(UserName=name)["PolicyNames"]
        return self.iam.list_role_policies(RoleName=name)["PolicyNames"]
