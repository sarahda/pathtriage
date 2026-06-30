# =============================================================================
# PathTriage — Azure attack path Z3
# Role assignment manipulation (self-grant Owner via UAA)
#
# Class                : IAM modification
# AWS analogue         : P5 (AttachPolicy self-attach)
# MITRE ATT&CK (Cloud) : T1098 — Account Manipulation
#
# Scenario:
#   VM with System-Assigned MI granted "User Access Administrator" scoped to
#   the resource group only (a plausible "delegated permission-management"
#   misconfiguration). The MI uses its UAA right to create a roleAssignments
#   PUT that grants itself Owner on the same RG — a horizontal RBAC pivot
#   that effectively converts UAA into Owner.
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
  rg_id     = data.terraform_remote_state.baseline_azure_personal.outputs.rg_id
  location  = data.terraform_remote_state.baseline_azure_personal.outputs.location
  subnet_id = data.terraform_remote_state.baseline_azure_personal.outputs.subnet_id
}

# ---- Foothold VM networking ----
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

# ---- VM with System-Assigned MI ----
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

# -----------------------------------------------------------------------------
# THE MISCONFIGURATION:
#   VM MI gets User Access Administrator scoped to the RG.
#   UAA includes Microsoft.Authorization/roleAssignments/write — sufficient
#   to self-grant any role at the same scope.
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "vm_mi_user_access_admin" {
  scope                = local.rg_id
  role_definition_name = "User Access Administrator"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}
