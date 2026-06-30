# =============================================================================
# PathTriage — Azure attack path Z2
# Service Principal credential theft via misconfigured App Service app_settings
#
# Class                : Credential discovery
# AWS analogue         : P7 (Lambda env-var theft)
# MITRE ATT&CK (Cloud) : T1552.001 — Unsecured Credentials: Credentials In Files
#
# Runs on baseline_azure_personal (personal MSA subscription) per D-Z2-01.
# =============================================================================

data "terraform_remote_state" "baseline_azure_personal" {
  backend = "local"
  config = {
    path = "../../baseline_azure_personal/terraform.tfstate"
  }
}

data "azurerm_subscription" "current" {}

locals {
  rg_name   = data.terraform_remote_state.baseline_azure_personal.outputs.rg_name
  location  = data.terraform_remote_state.baseline_azure_personal.outputs.location
  subnet_id = data.terraform_remote_state.baseline_azure_personal.outputs.subnet_id
}

# ---- Networking for foothold VM ----
resource "azurerm_public_ip" "vm" {
  name                = "${var.name_prefix}-pip"
  resource_group_name = local.rg_name
  location            = local.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "vm" {
  name                = "${var.name_prefix}-nsg"
  resource_group_name = local.rg_name
  location            = local.location

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "vm" {
  name                = "${var.name_prefix}-nic"
  resource_group_name = local.rg_name
  location            = local.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = local.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_network_interface_security_group_association" "vm" {
  network_interface_id      = azurerm_network_interface.vm.id
  network_security_group_id = azurerm_network_security_group.vm.id
}

# ---- Foothold VM with System-Assigned MI ----
resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "${var.name_prefix}-vm"
  resource_group_name   = local.rg_name
  location              = local.location
  size                  = "Standard_D2s_v3"
  admin_username        = var.vm_admin_username
  network_interface_ids = [azurerm_network_interface.vm.id]

  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = file(pathexpand(var.ssh_public_key_path))
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(<<-CLOUDINIT
    #cloud-config
    package_update: true
    packages:
      - python3-pip
    runcmd:
      - pip3 install --quiet requests
  CLOUDINIT
  )
}

# ---- Misconfiguration target: Web App with leaked SP creds ----
resource "random_string" "app_suffix" {
  length  = 6
  upper   = false
  special = false
}

resource "azurerm_service_plan" "asp" {
  name                = "${var.name_prefix}-asp"
  resource_group_name = local.rg_name
  location            = local.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "app" {
  name                = "${var.name_prefix}-app-${random_string.app_suffix.result}"
  resource_group_name = local.rg_name
  location            = azurerm_service_plan.asp.location
  service_plan_id     = azurerm_service_plan.asp.id

  site_config {}

  app_settings = {
    "WEBSITES_PORT" = "8080"
    "ENV"           = "prod"

    "AZURE_TENANT_ID"     = var.elevated_sp_tenant_id
    "AZURE_CLIENT_ID"     = var.elevated_sp_client_id
    "AZURE_CLIENT_SECRET" = var.elevated_sp_client_secret
  }
}

# ---- Over-broad grant: VM MI -> Website Contributor on ONE app ----
resource "azurerm_role_assignment" "vm_mi_website_contributor" {
  scope                = azurerm_linux_web_app.app.id
  role_definition_name = "Website Contributor"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}
