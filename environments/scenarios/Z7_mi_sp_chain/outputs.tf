output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "vm_ssh_command" {
  value = "ssh ${var.vm_admin_username}@${azurerm_public_ip.vm.ip_address}"
}

output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "resource_group_name" {
  value = local.rg_name
}

output "resource_group_id" {
  value = local.rg_id
}

output "sp_a_app_id" {
  value     = var.sp_a_app_id
  sensitive = true
}

output "sp_b_app_id" {
  value     = var.sp_b_app_id
  sensitive = true
}
