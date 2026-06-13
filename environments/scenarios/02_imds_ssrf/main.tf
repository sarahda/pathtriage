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
      Scenario  = "02_imds_ssrf"
    }
  }
}

# Reference baseline outputs (VPC, subnet, low-priv user)
data "terraform_remote_state" "baseline" {
  backend = "local"
  config = {
    path = "../../baseline/terraform.tfstate"
  }
}

# ============================================================
# Target role: the credentials we want to steal via IMDS.
# Given S3 read-only so the stolen creds demonstrably DO something
# (impact is observable without granting full admin).
# ============================================================
resource "aws_iam_role" "instance_role" {
  name = "pathtriage-imds-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "instance_role_s3" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "pathtriage-imds-instance-profile"
  role = aws_iam_role.instance_role.name
}

# ============================================================
# Security group: expose the Flask app (5000) to the attacker.
# Restrict source via var.attacker_cidr (default 0.0.0.0/0 for lab).
# ============================================================
resource "aws_security_group" "web_sg" {
  name        = "pathtriage-imds-web-sg"
  description = "PathTriage IMDS SSRF lab - exposes vulnerable Flask app"
  vpc_id      = data.terraform_remote_state.baseline.outputs.vpc_id

  ingress {
    description = "Vulnerable Flask app"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [var.attacker_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ============================================================
# Latest Amazon Linux 2023 AMI
# ============================================================
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# ============================================================
# Vulnerable EC2 instance.
# THE MISCONFIGURATION: http_tokens = "optional" => IMDSv1 allowed.
# An SSRF in the app can reach 169.254.169.254 with no token.
# ============================================================
resource "aws_instance" "vulnerable_web" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  subnet_id                   = data.terraform_remote_state.baseline.outputs.public_subnet_id
  vpc_security_group_ids      = [aws_security_group.web_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.instance_profile.name
  associate_public_ip_address = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # <-- IMDSv1 NOT enforced (the vulnerability)
    http_put_response_hop_limit = 2          # allows app container -> IMDS if containerised
  }

  user_data = file("${path.module}/user_data.sh")

  tags = { Name = "pathtriage-imds-vulnerable-web" }
}
