output "leaky_bucket_name" {
  value = aws_s3_bucket.leaky.id
}

output "leaked_user_arn" {
  value = aws_iam_user.leaked_identity.arn
}

output "scenario_summary" {
  value = <<-EOT
    Scenario 08: S3 Credential Harvest
    Starting credentials: baseline's low_priv_attacker user.
    Misconfiguration:     an S3 bucket (${aws_s3_bucket.leaky.id}) holds two
                          objects with the same admin user's long-term keys
                          in cleartext:
                            - app/configs/deployment.env (env-file format)
                            - infra/prod/terraform.tfstate (TF state format)
                          The low-priv user has s3:ListAllMyBuckets +
                          s3:ListBucket + s3:GetObject on all buckets.
    Target:               the embedded IAM user's long-term access keys.
    Exploit path:
    1. Use low-priv credentials
    2. s3:ListAllMyBuckets -> enumerate buckets
    3. s3:ListBucket on each -> identify credential-bearing files by
       extension/name heuristics (.env, .tfstate, credentials*, secret*)
    4. s3:GetObject on candidates -> parse multi-format (tfstate JSON,
       .env KEY=VALUE, generic AKIA regex)
    5. Use harvested credentials off-band (boto3 Session) -> confirm admin
    Catalogue note: like Path 7, invisible to IAM-permission-graph tools.
    The misconfiguration lives in bucket content, not in IAM policy.
  EOT
}