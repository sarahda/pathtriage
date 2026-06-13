variable "aws_region" {
  type    = string
  default = "ap-southeast-2"
}

variable "attacker_cidr" {
  description = "Source CIDR allowed to reach the vulnerable Flask app. Lock to your IP for a real lab; 0.0.0.0/0 for quick local testing only."
  type        = string
  default     = "0.0.0.0/0"
}
