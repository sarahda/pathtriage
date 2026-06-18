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
      Scenario  = "05_attachpolicy"
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
# Scenario 05: AttachPolicy Escalation (the baseline path)
#
# The low-priv user holds iam:AttachUserPolicy scoped to their OWN ARN.
# This is the simplest possible IAM escalation primitive:
#   - one API call (no version dance, no trust manipulation, no chain)
#   - attaches an existing AWS-managed policy as-is
#   - no IAM resource is modified; only an attachment is added
#
# This path is the *baseline* against which Paths 3 (CreatePolicyVersion)
# and 4 (AssumeRole chain) should be ranked as less-obvious variants of
# the same "modify your way in" idea. The exploitability rubric should
# score Path 05 strictly higher on ease than Paths 3 or 4 — a useful
# sanity check that the rubric reflects reality.
# ============================================================

locals {
  escalation_policy_name = "pathtriage-attachpolicy-target"
  low_priv_user_arn      = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/${data.terraform_remote_state.baseline.outputs.low_priv_user_name}"
}

resource "aws_iam_policy" "escalatable" {
  name        = local.escalation_policy_name
  description = "PathTriage Path 05 - grants iam:AttachUserPolicy scoped to self"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadOnlyBaseline"
        Effect   = "Allow"
        Action   = ["iam:Get*", "iam:List*", "sts:GetCallerIdentity"]
        Resource = "*"
      },
      {
        Sid      = "DangerousAttachOnSelf"
        Effect   = "Allow"
        Action   = "iam:AttachUserPolicy"
        Resource = local.low_priv_user_arn
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_escalatable" {
  user       = data.terraform_remote_state.baseline.outputs.low_priv_user_name
  policy_arn = aws_iam_policy.escalatable.arn
}