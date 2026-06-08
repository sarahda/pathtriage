output "vpc_id" {
  description = "VPC ID for scenario modules to reference"
  value       = aws_vpc.pathtriage.id
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = aws_subnet.public.id
}

output "low_priv_user_name" {
  description = "Low-privilege starting user name"
  value       = aws_iam_user.low_priv_attacker.name
}

output "low_priv_access_key_id" {
  description = "Access key ID for low-priv user"
  value       = aws_iam_access_key.low_priv_attacker.id
  sensitive   = true
}

output "low_priv_secret_access_key" {
  description = "Secret access key for low-priv user"
  value       = aws_iam_access_key.low_priv_attacker.secret
  sensitive   = true
}