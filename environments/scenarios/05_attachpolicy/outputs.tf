output "escalation_policy_arn" {
  value = aws_iam_policy.escalatable.arn
}

output "scenario_summary" {
  value = <<-EOT
    Scenario 05: AttachPolicy Escalation (the baseline path)
    Starting credentials: baseline's low_priv_attacker user.
    Misconfiguration:     a customer-managed policy attached to the user
                          grants iam:AttachUserPolicy scoped to the user's
                          own ARN.
    Target:               the user's own effective permissions.
    Exploit path:
    1. Use low-priv credentials
    2. iam:AttachUserPolicy(UserName=self,
                            PolicyArn=arn:aws:iam::aws:policy/AdministratorAccess)
    3. The user is now effectively admin — confirm with a privileged call
       that was denied before (e.g. iam:CreateUser)
    4. Cleanup: detach AdministratorAccess from the user before returning,
       so the lab returns to its starting state and terraform destroy
       leaves no orphan attachment.
    The simplest possible escalation primitive: one API call, no IAM
    resource modification, no role assumption.
  EOT
}