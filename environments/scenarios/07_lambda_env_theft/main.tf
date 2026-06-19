terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
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
      Scenario  = "07_lambda_env_theft"
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
# Scenario 07: Lambda Environment-Variable Credential Theft
#
# Lambda functions commonly hold AWS credentials, database connection
# strings, or API tokens as plaintext environment variables. A user with
# lambda:GetFunctionConfiguration can read those env vars directly without
# invoking the function or interacting with the IAM layer in any privileged
# way. This is *credential discovery* — not credential generation.
#
# Two layers of misconfiguration are demonstrated here:
#   1. A long-term IAM user with admin privileges exists at all (vs using
#      IAM roles or short-lived STS credentials)
#   2. The user's access keys are stored in plaintext env vars (vs Secrets
#      Manager / Parameter Store / KMS-encrypted runtime injection)
#
# Why this matters for the catalogue:
#   - PMapper and BloodHound OpenGraph operate at the IAM permission layer
#     and have no visibility into Lambda function configuration content.
#     This path is invisible to them. It surfaces a class of finding the
#     existing tools cannot enumerate — direct evidence for N3 (validated
#     catalogue) in the project proposal.
#   - Defender output for this path is log-based on Lambda API usage
#     patterns (GetFunctionConfiguration + off-band use of the leaked key),
#     not on IAM policy events. This is the "credential discovery"
#     convergence point (with Path 8) in the W7 defender-output design.
#
# Reserved env var names note:
#   AWS Lambda rejects AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY as
#   reserved keys. The misconfiguration is therefore modelled with
#   BACKUP_AWS_* prefixed names — a more realistic pattern in any case,
#   matching real-world breaches where developers prefix service-account
#   keys ("backup user", "deploy user", "legacy export user", etc.).
# ============================================================

# ------------------------------------------------------------
# The privileged identity whose long-term keys will be stolen.
# In a real breach, this is often a "service account" that pre-dates
# the org's move to IAM roles.
# ------------------------------------------------------------
resource "aws_iam_user" "leaked_identity" {
  name = "pathtriage-07-backup-user"
}

resource "aws_iam_user_policy_attachment" "leaked_identity_admin" {
  user       = aws_iam_user.leaked_identity.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "leaked_identity" {
  user = aws_iam_user.leaked_identity.name
}

# ------------------------------------------------------------
# The Lambda's execution role (minimal — basic execution only).
# ------------------------------------------------------------
resource "aws_iam_role" "lambda_exec" {
  name = "pathtriage-07-lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_exec_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ------------------------------------------------------------
# The misconfigured Lambda — innocuous-looking, but with privileged keys
# in env vars to (notionally) authenticate to a cross-account backup bucket.
# ------------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"
  source {
    content  = "def handler(event, context):\n    return {'status': 'PathTriage 07 lab — env vars are the issue'}\n"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "with_secrets" {
  function_name    = "pathtriage-07-internal-data-sync"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      # The misconfiguration — admin keys in plaintext env vars
      BACKUP_AWS_ACCESS_KEY_ID     = aws_iam_access_key.leaked_identity.id
      BACKUP_AWS_SECRET_ACCESS_KEY = aws_iam_access_key.leaked_identity.secret
      # plausible-looking decoy env vars
      LOG_LEVEL   = "INFO"
      ENVIRONMENT = "production"
      BUCKET_NAME = "internal-data-backup-bucket"
    }
  }
}

# ------------------------------------------------------------
# Low-priv user permissions: read-only Lambda access (no Invoke).
# This is the surprisingly common misconfiguration — many orgs grant
# lambda:Get* / List* for "monitoring" or "audit" purposes without
# realising it exposes function env vars.
# ------------------------------------------------------------
resource "aws_iam_user_policy" "low_priv_can_read_lambda" {
  name = "pathtriage-07-can-read-lambda"
  user = data.terraform_remote_state.baseline.outputs.low_priv_user_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DangerousLambdaRead"
      Effect = "Allow"
      Action = [
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "lambda:GetFunction",
      ]
      Resource = "*"
    }]
  })
}