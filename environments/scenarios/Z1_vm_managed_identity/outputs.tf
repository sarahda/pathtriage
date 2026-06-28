output "vm_public_ip" {
  value = azurerm_public_ip.victim.ip_address
}

output "vm_mi_principal_id" {
  value = azurerm_linux_virtual_machine.victim.identity[0].principal_id
}
