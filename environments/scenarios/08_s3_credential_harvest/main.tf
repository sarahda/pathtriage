terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "PathTriage"
      ManagedBy = "Terraform"
      Scenario  = "08_s3_credential_harvest"
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
# Scenario 08: S3 Credential Harvest
#
# Low-priv user has broad S3 read permissions. An S3 bucket in the account
# contains files holding AWS credentials in cleartext:
#   - app/configs/deployment.env  — classic .env file pattern
#   - infra/prod/terraform.tfstate — Terraform state file with raw secret
#
# The attacker enumerates buckets, lists objects, downloads candidates by
# extension/name heuristics, parses each file for credential-shaped values,
# and uses the harvested keys off-band.
#
# Terraform state files are particularly important to model: developers
# routinely store state in S3, and state files contain aws_iam_access_key
# resources with raw `secret` attributes in cleartext. This is the canonical
# real-world failure mode for "state file in S3" misconfigurations.
#
# Catalogue significance:
#   - Like Path 7, this surfaces a class of finding *invisible to IAM-layer
#     analysis tools* (PMapper, BloodHound). The misconfiguration lives in
#     bucket *contents*, not in IAM policy.
#   - Paths 7 and 8 form the credential-discovery convergence point — a
#     single defender output (Lambda/S3 API + off-band key use correlation)
#     covers both (N2).
# ============================================================

# ------------------------------------------------------------
# The privileged identity whose long-term keys appear in the bucket.
# ------------------------------------------------------------
resource "aws_iam_user" "leaked_identity" {
  name = "pathtriage-08-deploy-user"
}

resource "aws_iam_user_policy_attachment" "leaked_admin" {
  user       = aws_iam_user.leaked_identity.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "leaked_identity" {
  user = aws_iam_user.leaked_identity.name
}

# ------------------------------------------------------------
# The leaky bucket. Globally unique name via random suffix.
# force_destroy=true so `terraform destroy` can wipe contents.
# Public access blocked — the breach is internal pivoting, not exposure.
# ------------------------------------------------------------
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "leaky" {
  bucket        = "pathtriage-08-infra-state-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "leaky" {
  bucket                  = aws_s3_bucket.leaky.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------
# Object 1: A realistic-looking Terraform state file with creds in cleartext.
# This is the canonical "state in S3 with embedded access keys" pattern.
# ------------------------------------------------------------
resource "aws_s3_object" "leaked_tfstate" {
  bucket       = aws_s3_bucket.leaky.id
  key          = "infra/prod/terraform.tfstate"
  content_type = "application/json"
  content = jsonencode({
    version           = 4
    terraform_version = "1.5.7"
    serial            = 42
    lineage           = "8f3c1a7d-prod-pathtriage-08"
    outputs           = {}
    resources = [
      {
        mode     = "managed"
        type     = "aws_iam_access_key"
        name     = "deploy_key"
        provider = "provider[\"registry.terraform.io/hashicorp/aws\"]"
        instances = [
          {
            attributes = {
              id     = aws_iam_access_key.leaked_identity.id
              secret = aws_iam_access_key.leaked_identity.secret
              user   = aws_iam_user.leaked_identity.name
              status = "Active"
            }
          }
        ]
      }
    ]
  })
}

# ------------------------------------------------------------
# Object 2: A deployment .env file with the same creds. Demonstrates that
# the exploit must handle multiple file formats.
# ------------------------------------------------------------
resource "aws_s3_object" "leaked_env" {
  bucket       = aws_s3_bucket.leaky.id
  key          = "app/configs/deployment.env"
  content_type = "text/plain"
  content      = <<-EOT
    # Deployment config — production
    LOG_LEVEL=INFO
    DB_HOST=prod-db.internal
    AWS_ACCESS_KEY_ID=${aws_iam_access_key.leaked_identity.id}
    AWS_SECRET_ACCESS_KEY=${aws_iam_access_key.leaked_identity.secret}
    S3_BUCKET=prod-artifacts
  EOT
}

# Decoy objects so enumeration looks realistic
resource "aws_s3_object" "decoy_readme" {
  bucket  = aws_s3_bucket.leaky.id
  key     = "README.md"
  content = "# Infrastructure state bucket\n\nDo not delete.\n"
}

resource "aws_s3_object" "decoy_log" {
  bucket  = aws_s3_bucket.leaky.id
  key     = "logs/2025-12/deploy.log"
  content = "2025-12-01 deployment completed\n2025-12-02 deployment completed\n"
}

# ------------------------------------------------------------
# Low-priv permissions: broad S3 read. In a real org these are routinely
# granted for "monitoring" or "data analytics" use cases.
# ------------------------------------------------------------
resource "aws_iam_user_policy" "low_priv_can_read_s3" {
  name = "pathtriage-08-can-read-s3"
  user = data.terraform_remote_state.baseline.outputs.low_priv_user_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DangerousS3Read"
      Effect = "Allow"
      Action = [
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:GetObject",
      ]
      Resource = "*"
    }]
  })
}