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
      Scenario  = "03_createpolicyversion"
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
# The escalatable customer-managed policy.
#
# It is ATTACHED TO THE LOW-PRIV USER and grants:
#   - a small read-only baseline (iam:Get*/List*)
#   - iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion *scoped to itself*
#
# Because the user can rewrite the very policy that defines their own
# permissions, they can mint a new default version granting *:* — no role
# assumption, no EC2. Pure IAM-layer escalation.
#
# The Resource must be the policy's own ARN. We build that ARN as a string
# from account-id + name to avoid a circular dependency (a policy document
# cannot reference its own resource handle during creation).
# ============================================================
locals {
  escalation_policy_name = "pathtriage-createpolicyversion-target"
  escalation_policy_arn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${local.escalation_policy_name}"
}

resource "aws_iam_policy" "escalatable" {
  name        = local.escalation_policy_name
  description = "PathTriage Path 03 - intentionally escalatable via CreatePolicyVersion"

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
        Sid    = "DangerousPolicyVersionPerms"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:DeletePolicyVersion"
        ]
        Resource = local.escalation_policy_arn
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_escalatable" {
  user       = data.terraform_remote_state.baseline.outputs.low_priv_user_name
  policy_arn = aws_iam_policy.escalatable.arn
}
