terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "PathTriage"
      ManagedBy = "Terraform"
      Scenario  = "04_assume_role_chain"
    }
  }
}

data "terraform_remote_state" "baseline" {
  backend = "local"
  config = {
    path = "../../baseline/terraform.tfstate"
  }
}

data "aws_caller_identity" "current" {}

# ============================================================
# Scenario 04: AssumeRole Chain
#
# Two roles forming a transitive trust topology:
#   R1 (intermediate)  — trusts the baseline low_priv user
#   R2 (admin)         — trusts R1
#
# The misconfiguration is NOT in any single role. Each individual trust
# relationship is reasonable in isolation (cross-account automation, role
# chaining for CI, etc). The vulnerability is the *transitive closure*:
# anyone who can become R1 can become R2 via a second AssumeRole hop.
#
# This is the catalogue's "no fingerprints" path:
#   - No IAM modification at all
#   - CloudTrail only sees sts:AssumeRole events (individually legitimate)
#   - Contrast with Path 3 (CreatePolicyVersion) and Path 5 (AttachPolicy)
#     which both leave clear IAM-modification breadcrumbs.
# ============================================================

locals {
  r1_name = "pathtriage-assume-role-chain-r1"
  r2_name = "pathtriage-assume-role-chain-r2"
  r2_arn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.r2_name}"

  low_priv_user_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${data.terraform_remote_state.baseline.outputs.low_priv_user_name}"
}

# ------------------------------------------------------------
# R1 — intermediate role
#   Trusts: the baseline low_priv user
#   Permissions: sts:AssumeRole on R2 (the misconfigured edge)
#                + a read-only baseline so it looks like a legitimate role
# ------------------------------------------------------------
resource "aws_iam_role" "r1_intermediate" {
  name = local.r1_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.low_priv_user_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "r1_can_assume_r2" {
  name = "can-assume-r2"
  role = aws_iam_role.r1_intermediate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeR2"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = local.r2_arn
      },
      {
        Sid      = "ReadOnlyBaseline"
        Effect   = "Allow"
        Action   = ["iam:Get*", "iam:List*", "sts:GetCallerIdentity"]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------
# R2 — admin role
#   Trusts: R1 only
#   Permissions: AdministratorAccess (AWS-managed)
# ------------------------------------------------------------
resource "aws_iam_role" "r2_admin" {
  name = local.r2_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.r1_intermediate.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "r2_admin" {
  role       = aws_iam_role.r2_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ------------------------------------------------------------
# Low-priv user permission: sts:AssumeRole on R1
# ------------------------------------------------------------
resource "aws_iam_user_policy" "low_priv_can_assume_r1" {
  name = "pathtriage-04-can-assume-r1"
  user = data.terraform_remote_state.baseline.outputs.low_priv_user_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeR1"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.r1_intermediate.arn
    }]
  })
}