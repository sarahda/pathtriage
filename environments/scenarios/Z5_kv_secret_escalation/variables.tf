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
  default     = "pathtriage-z5"
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

variable "elevated_sp_app_id" {
  description = "Elevated SP's application (client) ID"
  type        = string
  sensitive   = true
}

variable "elevated_sp_client_secret" {
  description = "Elevated SP's client secret"
  type        = string
  sensitive   = true
}
