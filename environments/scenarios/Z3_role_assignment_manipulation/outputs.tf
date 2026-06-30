output "vm_public_ip"        { value = azurerm_public_ip.vm.ip_address }
output "vm_ssh_command"      { value = "ssh ${var.vm_admin_username}@${azurerm_public_ip.vm.ip_address}" }
output "vm_mi_principal_id"  { value = azurerm_linux_virtual_machine.vm.identity[0].principal_id }
output "resource_group_name" { value = data.terraform_remote_state.baseline_azure_personal.outputs.rg_name }
output "resource_group_id"   { value = data.terraform_remote_state.baseline_azure_personal.outputs.rg_id }
output "subscription_id"     { value = data.azurerm_subscription.current.subscription_id }
