output "vm_a_public_ip" {
  value = azurerm_public_ip.vm_a.ip_address
}

output "vm_a_ssh_command" {
  value = "ssh ${var.vm_admin_username}@${azurerm_public_ip.vm_a.ip_address}"
}

output "vm_a_mi_principal_id" {
  value = azurerm_linux_virtual_machine.vm_a.identity[0].principal_id
}

output "vm_b_name" {
  value = azurerm_linux_virtual_machine.vm_b.name
}

output "vm_b_id" {
  value = azurerm_linux_virtual_machine.vm_b.id
}

output "vm_b_mi_principal_id" {
  value = azurerm_linux_virtual_machine.vm_b.identity[0].principal_id
}

output "custom_role_name" {
  value = azurerm_role_definition.vm_diagnostic_runner.name
}

output "custom_role_id" {
  value = azurerm_role_definition.vm_diagnostic_runner.role_definition_resource_id
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
