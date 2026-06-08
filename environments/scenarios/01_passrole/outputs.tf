output "admin_role_arn" {
  description = "ARN of the target admin role"
  value       = aws_iam_role.admin_role.arn
}

output "admin_role_name" {
  description = "Name of the target admin role"
  value       = aws_iam_role.admin_role.name
}

output "instance_profile_name" {
  description = "Name of the instance profile to pass to EC2"
  value       = aws_iam_instance_profile.admin_profile.name
}

output "vulnerable_user_name" {
  description = "Name of the low-priv user with vulnerable permissions"
  value       = data.terraform_remote_state.baseline.outputs.low_priv_user_name
}

output "scenario_summary" {
  description = "Exploit path summary"
  value       = <<-EOT
    
    ╔════════════════════════════════════════════════════════════╗
    ║  Scenario 01: PassRole + Service Abuse                     ║
    ╚════════════════════════════════════════════════════════════╝
    
    Starting credentials: baseline's low_priv_attacker
    
    Misconfiguration: 
      User has iam:PassRole + ec2:RunInstances on this admin role
    
    Target:
      Admin role: ${aws_iam_role.admin_role.name}
      ARN: ${aws_iam_role.admin_role.arn}
      Instance profile: ${aws_iam_instance_profile.admin_profile.name}
    
    Exploit path:
      1. Use low-priv credentials (from baseline)
      2. Discover passable roles via iam:ListRoles
      3. Launch EC2 instance with admin instance profile
      4. Connect to EC2 (SSM or SSH)
      5. Extract credentials from IMDS:
         curl http://169.254.169.254/latest/meta-data/iam/security-credentials/${aws_iam_role.admin_role.name}
      6. Use admin credentials for full account compromise
    
    MITRE ATT&CK: T1548.005 (Abuse Elevation Control Mechanism)
    
  EOT
}