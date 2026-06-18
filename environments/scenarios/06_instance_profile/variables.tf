variable "aws_region" {
  type    = string
  default = "ap-southeast-2"
}

variable "ssh_cidr" {
  type        = string
  description = "CIDR allowed to SSH into the lab EC2. Default 0.0.0.0/0 for lab simplicity; override with your /32 in real use."
  default     = "0.0.0.0/0"
}