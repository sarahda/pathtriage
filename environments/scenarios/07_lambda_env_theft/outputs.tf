output "lambda_function_name" {
  value = aws_lambda_function.with_secrets.function_name
}

output "leaked_user_arn" {
  value = aws_iam_user.leaked_identity.arn
}

output "scenario_summary" {
  value = <<-EOT
    Scenario 07: Lambda Environment-Variable Credential Theft
    Starting credentials: baseline's low_priv_attacker user.
    Misconfiguration:     a Lambda function (${aws_lambda_function.with_secrets.function_name})
                          holds long-term IAM access keys of a privileged user
                          (${aws_iam_user.leaked_identity.name}) in plaintext
                          environment variables (BACKUP_AWS_ACCESS_KEY_ID,
                          BACKUP_AWS_SECRET_ACCESS_KEY). The low-priv user has
                          lambda:ListFunctions + GetFunctionConfiguration on
                          all functions, allowing env-var read without invoke.
    Target:               the embedded IAM user's long-term access keys.
    Exploit path:
    1. Use low-priv credentials
    2. lambda:ListFunctions -> enumerate functions
    3. lambda:GetFunctionConfiguration on each -> read env vars
    4. Pattern-match AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in env keys
    5. Use the harvested credentials off-band (boto3 Session) to confirm
       admin (e.g. iam:CreateUser)
    Critical property: extracted keys are AKIA-prefixed *long-term* keys,
    valid until rotated — unlike IMDS temp credentials (Path 6, ASIA, ~1h).
    Tooling note: PMapper and BloodHound cannot detect this path — they
    operate at the IAM permission layer with no visibility into Lambda
    function configuration content.
  EOT
}