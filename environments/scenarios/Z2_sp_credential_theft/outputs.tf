output "vm_public_ip"        { value = azurerm_public_ip.vm.ip_address }
output "vm_ssh_command"      { value = "ssh ${var.vm_admin_username}@${azurerm_public_ip.vm.ip_address}" }
output "web_app_name"        { value = azurerm_linux_web_app.app.name }
output "web_app_resource_id" { value = azurerm_linux_web_app.app.id }
output "resource_group_name" { value = data.terraform_remote_state.baseline_azure_personal.outputs.rg_name }
output "subscription_id"     { value = data.azurerm_subscription.current.subscription_id }

output "elevated_sp_client_id" {
  value     = var.elevated_sp_client_id
  sensitive = true
}
