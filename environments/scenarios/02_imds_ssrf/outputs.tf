output "instance_public_ip" {
  value = aws_instance.vulnerable_web.public_ip
}

output "app_url" {
  value = "http://${aws_instance.vulnerable_web.public_ip}:5000"
}

output "instance_role_name" {
  value = aws_iam_role.instance_role.name
}

output "scenario_summary" {
  value = <<-EOT
    Scenario 02: IMDS SSRF Credential Theft

    Starting position: network access to the vulnerable Flask app only
                       (NO AWS credentials required to begin).
    Misconfiguration:  EC2 has IMDSv1 enabled (http_tokens = "optional")
                       AND runs an app with an SSRF flaw (/fetch?url=).
    Target:            instance role (${aws_iam_role.instance_role.name}),
                       which holds AmazonS3ReadOnlyAccess.

    Exploit path:
    1. Hit /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    2. Read the role name, then fetch that role's temporary credentials
    3. Use the stolen AccessKey/Secret/Token with boto3
    4. Confirm via sts:GetCallerIdentity; demonstrate S3 read access

    App URL: http://${aws_instance.vulnerable_web.public_ip}:5000
  EOT
}
