output "instance_id" {
  value = aws_instance.lab.id
}

output "instance_public_ip" {
  value = aws_instance.lab.public_ip
}

output "ssh_key_path" {
  value = abspath(local_sensitive_file.private_key.filename)
}

output "role_name" {
  value = aws_iam_role.ec2_admin.name
}

output "ssh_command" {
  value = "ssh -i ${local_sensitive_file.private_key.filename} -o StrictHostKeyChecking=no ec2-user@${aws_instance.lab.public_ip}"
}

output "scenario_summary" {
  value = <<-EOT
    Scenario 06: EC2 Instance Profile Abuse (IMDS credential extraction)
    Starting position:    attacker has shell on the lab EC2 (modelled via SSH
                          for reproducibility; foothold method is out of scope,
                          consistent with Path 1).
    Misconfiguration:     the EC2 has AdministratorAccess via instance profile.
                          IMDSv2 is enforced, but the role itself is over-priv'd.
    Target:               the instance role's temporary credentials.
    Exploit path:
    1. SSH to the EC2 (foothold — out of scope)
    2. IMDSv2 token: PUT /latest/api/token
    3. Read role name: GET /latest/meta-data/iam/security-credentials/
    4. Read credentials: GET /latest/meta-data/iam/security-credentials/<role>
    5. Use AccessKeyId/SecretAccessKey/Token *off-box* via boto3 to confirm
       admin (e.g. iam:CreateUser)
    Convergence: Paths 1, 2, 6 all terminate in IMDS extraction; a single
    detection at IMDS-read+off-box-use covers all three.
  EOT
}