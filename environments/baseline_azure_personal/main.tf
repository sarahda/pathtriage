# baseline_azure_personal — shared infra for Z2-Z8 on the personal MSA
# subscription (UNSW tenant blocks SP creation, so cred-disc paths run here).
# Z1 stays on baseline_azure (UNSW). See attacks/Z2_sp_credential_theft/README.md
# D-Z2-01 for rationale.

resource "azurerm_resource_group" "rg" {
  name     = "${var.name_prefix}-rg"
  location = var.location

  tags = {
    Project  = "PathTriage"
    Scope    = "baseline_azure_personal"
    Subscope = "Z2-Z8"
  }
}

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.name_prefix}-vnet"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "subnet" {
  name                 = "${var.name_prefix}-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}
