output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "vm_ssh_command" {
  value = "ssh ${var.vm_admin_username}@${azurerm_public_ip.vm.ip_address}"
}

output "vm_mi_principal_id" {
  value = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

output "key_vault_name" {
  value = azurerm_key_vault.vault.name
}

output "key_vault_uri" {
  value = azurerm_key_vault.vault.vault_uri
}

output "secret_name" {
  value = azurerm_key_vault_secret.elevated_sp_secret.name
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
