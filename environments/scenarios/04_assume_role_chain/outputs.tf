output "r1_arn" {
  value = aws_iam_role.r1_intermediate.arn
}

output "r2_arn" {
  value = aws_iam_role.r2_admin.arn
}

output "scenario_summary" {
  value = <<-EOT
    Scenario 04: AssumeRole Chain (no-fingerprints escalation)
    Starting credentials: baseline's low_priv_attacker user.
    Misconfiguration:     a transitive trust topology
                            low_priv_user -> R1 (${aws_iam_role.r1_intermediate.arn})
                                          -> R2 (${aws_iam_role.r2_admin.arn})
                          where R1 trusts the user, R2 trusts R1, and R1 holds
                          sts:AssumeRole on R2. Each hop is individually
                          legitimate; the chain in aggregate is not.
    Target:               R2 (AdministratorAccess).
    Exploit path:
    1. Use low-priv credentials
    2. sts:AssumeRole on R1 -> temporary R1 credentials
    3. sts:AssumeRole on R2 using R1 creds -> temporary R2 credentials
    4. R2 credentials now have *:* — confirm with a privileged call
       that was denied for both low_priv_user and R1 (e.g. iam:CreateUser)
    No IAM modification anywhere; only sts:AssumeRole events in CloudTrail.
  EOT
}