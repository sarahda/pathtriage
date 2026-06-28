output "rg_name" {
  value = azurerm_resource_group.pathtriage.name
}

output "rg_id" {
  value = azurerm_resource_group.pathtriage.id
}

output "location" {
  value = azurerm_resource_group.pathtriage.location
}

output "subnet_id" {
  value = azurerm_subnet.public.id
}

output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}

output "current_user_object_id" {
  value = data.azurerm_client_config.current.object_id
}
