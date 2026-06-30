variable "location" {
  type    = string
  default = "australiaeast"
}

variable "name_prefix" {
  type    = string
  default = "pathtriage-z2"
}

variable "vm_admin_username" {
  type    = string
  default = "azureuser"
}

variable "ssh_public_key_path" {
  type    = string
  default = "~/.ssh/id_rsa.pub"
}

variable "elevated_sp_client_id"     { type = string }
variable "elevated_sp_client_secret" {
  type      = string
  sensitive = true
}
variable "elevated_sp_tenant_id" { type = string }
variable "elevated_sp_object_id" { type = string }
