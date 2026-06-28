# Resource Group — all PathTriage Azure resources live here
resource "azurerm_resource_group" "pathtriage" {
  name     = "pathtriage-rg"
  location = "australiaeast"
}

# VNet + subnet for victim VMs
resource "azurerm_virtual_network" "pathtriage" {
  name                = "pathtriage-vnet"
  address_space       = ["10.10.0.0/16"]
  location            = azurerm_resource_group.pathtriage.location
  resource_group_name = azurerm_resource_group.pathtriage.name
}

resource "azurerm_subnet" "public" {
  name                 = "pathtriage-subnet-public"
  resource_group_name  = azurerm_resource_group.pathtriage.name
  virtual_network_name = azurerm_virtual_network.pathtriage.name
  address_prefixes     = ["10.10.1.0/24"]
}

data "azurerm_subscription" "current" {}

data "azurerm_client_config" "current" {}
