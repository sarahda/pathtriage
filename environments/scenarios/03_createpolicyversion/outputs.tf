output "escalation_policy_arn" {
  value = aws_iam_policy.escalatable.arn
}

output "scenario_summary" {
  value = <<-EOT
    Scenario 03: CreatePolicyVersion Privilege Escalation (pure IAM)

    Starting credentials: baseline's low_priv_attacker user.
    Misconfiguration:     a customer-managed policy is attached to the user and
                          grants iam:CreatePolicyVersion + SetDefaultPolicyVersion
                          on its OWN ARN.
    Target:               the user's own effective permissions.

    Exploit path:
    1. Use low-priv credentials
    2. Create a NEW version of ${aws_iam_policy.escalatable.arn}
       whose document allows Action "*" on Resource "*"
    3. Set that version as default (--set-as-default)
    4. The user is now effectively admin — confirm with a privileged call
       that was denied before (e.g. iam:CreateUser)

    No EC2 instance and no role assumption involved.
  EOT
}
