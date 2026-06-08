terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5"
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "PathTriage"
      ManagedBy = "Terraform"
      Scenario  = "01_passrole"
    }
  }
}

# ============================================================
# Reference baseline outputs (VPC, low-priv user)
# ============================================================

data "terraform_remote_state" "baseline" {
  backend = "local"
  config = {
    path = "../../baseline/terraform.tfstate"
  }
}

# ============================================================
# Target: Admin role that EC2 can assume
# ============================================================

resource "aws_iam_role" "admin_role" {
  name = "pathtriage-passrole-admin-target"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# Attach AdministratorAccess to make this role attractive to attackers
resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Instance profile so EC2 can use the role
resource "aws_iam_instance_profile" "admin_profile" {
  name = "pathtriage-passrole-admin-profile"
  role = aws_iam_role.admin_role.name
}

# ============================================================
# Misconfiguration: Low-priv user has iam:PassRole + ec2:RunInstances
# This is the vulnerable combination — they can launch EC2 with admin role
# ============================================================

resource "aws_iam_user_policy" "vulnerable_passrole" {
  name = "pathtriage-vulnerable-passrole-policy"
  user = data.terraform_remote_state.baseline.outputs.low_priv_user_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPassRoleToEC2"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = aws_iam_role.admin_role.arn
      },
      {
        Sid    = "AllowEC2Operations"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:DescribeImages",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateTags",
          "iam:GetInstanceProfile",
          "iam:ListInstanceProfiles",
          "iam:ListRoles",
          "iam:GetRole"
        ]
        Resource = "*"
      }
    ]
  })
}