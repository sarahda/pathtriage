variable "subscription_id" {
  description = "Azure subscription ID (personal MSA)"
  type        = string
  default     = null
}

variable "tenant_id" {
  description = "Azure tenant ID"
  type        = string
  default     = null
}

variable "name_prefix" {
  description = "Prefix for all resources in this scenario"
  type        = string
  default     = "pathtriage-z7"
}

variable "vm_admin_username" {
  description = "Admin username for the foothold VM"
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key file (RSA only per D-Z4-04)"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "sp_a_app_id" {
  description = "SP-A app ID (attacker's compromised identity)"
  type        = string
  sensitive   = true
}

variable "sp_a_client_secret" {
  description = "SP-A client secret"
  type        = string
  sensitive   = true
}

variable "sp_b_app_id" {
  description = "SP-B app ID (elevated identity — impersonation target)"
  type        = string
  sensitive   = true
}
