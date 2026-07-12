output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "vm_ssh_command" {
  value = "ssh ${var.vm_admin_username}@${azurerm_public_ip.vm.ip_address}"
}

output "vm_mi_principal_id" {
  value = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

output "storage_account_name" {
  value = azurerm_storage_account.sa.name
}

output "storage_account_id" {
  value = azurerm_storage_account.sa.id
}

output "container_name" {
  value = azurerm_storage_container.tfstate.name
}

output "blob_name" {
  value = azurerm_storage_blob.tfstate.name
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

output "elevated_sp_app_id" {
  value     = var.elevated_sp_app_id
  sensitive = true
}
