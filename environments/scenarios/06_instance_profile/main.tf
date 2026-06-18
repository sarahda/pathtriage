terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "PathTriage"
      ManagedBy = "Terraform"
      Scenario  = "06_instance_profile"
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

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# ============================================================
# Scenario 06: EC2 Instance Profile Abuse
#
# An EC2 instance has an AdministratorAccess role attached via instance
# profile. An attacker who has reached the instance — by any means — reads
# IMDS to extract the role's temporary credentials, then uses them off-box.
#
# The "how the attacker got on the EC2" is intentionally outside the
# catalogued primitive (consistent with Path 1). This lab provisions SSH
# purely so the IMDS-extraction step can be reproduced cleanly.
#
# IMDSv2 is enforced (httpTokens=required). The point: even hardened IMDSv2
# hands out credentials to anyone with shell on the instance. The real fix
# is role posture, not IMDS posture.
#
# Convergence with Paths 1 and 2:
#   Path 1: attacker LAUNCHES a new EC2 with admin role (PassRole)
#   Path 2: attacker reaches IMDS through SSRF on someone else's EC2
#   Path 6: attacker is ALREADY ON the EC2 (this path)
# All three terminate in IMDS credential extraction — one defender rule
# at the IMDS-read+off-box-use pattern covers all three (N2 argument).
# ============================================================

resource "tls_private_key" "lab" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "lab" {
  key_name   = "pathtriage-06-key"
  public_key = tls_private_key.lab.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.lab.private_key_pem
  filename        = "${path.module}/pathtriage-06-key.pem"
  file_permission = "0400"
}

resource "aws_security_group" "lab" {
  name        = "pathtriage-06-sg"
  description = "Path 06 lab - SSH access"
  vpc_id      = data.terraform_remote_state.baseline.outputs.vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }

  egress {
    description = "all out"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------------------------------------
# The misconfigured role: AdministratorAccess on an EC2-trusted role.
# ------------------------------------------------------------
resource "aws_iam_role" "ec2_admin" {
  name = "pathtriage-06-ec2-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_admin" {
  role       = aws_iam_role.ec2_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "ec2_admin" {
  name = "pathtriage-06-ec2-admin-profile"
  role = aws_iam_role.ec2_admin.name
}

# ------------------------------------------------------------
# The EC2 instance — IMDSv2 ENFORCED to make the point explicit.
# ------------------------------------------------------------
resource "aws_instance" "lab" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  subnet_id                   = data.terraform_remote_state.baseline.outputs.public_subnet_id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.lab.id]
  key_name                    = aws_key_pair.lab.key_name
  iam_instance_profile        = aws_iam_instance_profile.ec2_admin.name

  metadata_options {
    http_tokens                 = "required" # IMDSv2 enforced
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "pathtriage-06-victim"
  }
}