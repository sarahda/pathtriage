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
      Scenario  = "baseline"
    }
  }
}

# Baseline VPC for all scenarios
resource "aws_vpc" "pathtriage" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "pathtriage-baseline-vpc"
  }
}

# Public subnet for EC2 scenarios
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.pathtriage.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "pathtriage-public-subnet"
  }
}

# Internet gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.pathtriage.id

  tags = {
    Name = "pathtriage-igw"
  }
}

# Route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.pathtriage.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "pathtriage-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Low-privilege starting user (attacker's starting point)
resource "aws_iam_user" "low_priv_attacker" {
  name = "pathtriage-low-priv-attacker"

  tags = {
    Purpose = "Starting point for privilege escalation scenarios"
  }
}

resource "aws_iam_access_key" "low_priv_attacker" {
  user = aws_iam_user.low_priv_attacker.name
}