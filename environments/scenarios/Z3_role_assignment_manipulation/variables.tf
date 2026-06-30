variable "location" {
  type    = string
  default = "australiaeast"
}

variable "name_prefix" {
  type    = string
  default = "pathtriage-z3"
}

variable "vm_admin_username" {
  type    = string
  default = "azureuser"
}

variable "ssh_public_key_path" {
  type    = string
  default = "~/.ssh/id_rsa.pub"
}
