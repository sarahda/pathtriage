# =============================================================================
# PathTriage — Azure attack path Z8
# VM Run Command Abuse (via runCommand extension)
#
# Class                : Compute hijack
# AWS analogue         : P1 (PassRole + RunInstances)
# MITRE ATT&CK (Cloud) : T1651 — Cloud Administration Command
#                        T1550.001 — Use Alternate Authentication Material:
#                                    Application Access Token
#
# Scenario:
#   Two VMs on the same subnet. VM-A hosts the attacker's foothold via a
#   compromised Managed Identity (MI-A). VM-B hosts an elevated Managed
#   Identity (MI-B) with subscription-level Contributor scope.
#
#   MI-A holds a custom role on VM-B that grants ONLY the runCommand
#   action — a scope that appears narrow and diagnostic-oriented but
#   effectively delegates full compute authority on VM-B. The attacker
#   uses runCommand to execute arbitrary code as root inside VM-B,
#   which queries the local IMDS endpoint to obtain MI-B's ARM token,
#   then exfiltrates that token via the runCommand response.
#
# Key design points:
#   - MI-A's role is a CUSTOM role, not the built-in "Virtual Machine
#     Contributor". Custom-role misconfigurations are more common in
#     the wild — operators often try to grant "just enough to run
#     diagnostics" without realising runCommand permits arbitrary code
#     execution as SYSTEM/root.
#   - The runCommand response returns stdout up to ~4KB. Azure MI
#     tokens are ~1800 chars — well within the response envelope. This
#     is the exfiltration channel.
#   - VM-B's MI has subscription-scope Contributor — this is the
#     escalation target. Any code running on VM-B can obtain a token
#     with that scope by querying IMDS.
#
# Why this is Z8 and distinct from Z1:
#   Z1 attacks the attacker's OWN VM's MI (extracts MI-A token via IMDS
#   on the compromised host). Z8 attacks a SEPARATE VM's MI via a
#   privileged control-plane action. The pivot is the point — Z1 is
#   single-VM privilege discovery, Z8 is cross-VM compute delegation.
# =============================================================================

data "terraform_remote_state" "baseline_azure_personal" {
  backend = "local"
  config = {
    path = "../../baseline_azure_personal/terraform.tfstate"
  }
}

data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}

locals {
  rg_name   = data.terraform_remote_state.baseline_azure_personal.outputs.rg_name
  rg_id     = data.terraform_remote_state.baseline_azure_personal.outputs.rg_id
  location  = data.terraform_remote_state.baseline_azure_personal.outputs.location
  subnet_id = data.terraform_remote_state.baseline_azure_personal.outputs.subnet_id
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

# =============================================================================
# VM-A — attacker's foothold (System-Assigned MI-A)
# =============================================================================

resource "azurerm_public_ip" "vm_a" {
  name                = "${var.name_prefix}-a-pip"
  resource_group_name = local.rg_name
  location            = local.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "vms" {
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

resource "azurerm_network_interface" "vm_a" {
  name                = "${var.name_prefix}-a-nic"
  resource_group_name = local.rg_name
  location            = local.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = local.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm_a.id
  }
}

resource "azurerm_network_interface_security_group_association" "vm_a" {
  network_interface_id      = azurerm_network_interface.vm_a.id
  network_security_group_id = azurerm_network_security_group.vms.id
}

resource "azurerm_linux_virtual_machine" "vm_a" {
  name                  = "${var.name_prefix}-a-vm"
  resource_group_name   = local.rg_name
  location              = local.location
  size                  = "Standard_D2s_v3"
  admin_username        = var.vm_admin_username
  network_interface_ids = [azurerm_network_interface.vm_a.id]

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

# =============================================================================
# VM-B — target (System-Assigned MI-B with subscription Contributor)
# =============================================================================

resource "azurerm_network_interface" "vm_b" {
  name                = "${var.name_prefix}-b-nic"
  resource_group_name = local.rg_name
  location            = local.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = local.subnet_id
    private_ip_address_allocation = "Dynamic"
    # No public IP — VM-B is internal only; attacker never touches it
    # directly, only via runCommand from VM-A.
  }
}

resource "azurerm_linux_virtual_machine" "vm_b" {
  name                  = "${var.name_prefix}-b-vm"
  resource_group_name   = local.rg_name
  location              = local.location
  size                  = "Standard_D2s_v3"
  admin_username        = var.vm_admin_username
  network_interface_ids = [azurerm_network_interface.vm_b.id]

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
}

# VM-B's MI holds Contributor at subscription scope — the escalation target.
resource "azurerm_role_assignment" "vm_b_mi_contributor" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_virtual_machine.vm_b.identity[0].principal_id
}

# =============================================================================
# THE MISCONFIGURATION — MI-A gets narrow runCommand action on VM-B only
# =============================================================================

# Custom role definition that grants ONLY runCommand action on VMs.
# In real-world scenarios, operators create such roles for "diagnostics"
# or "remote troubleshooting" purposes, not realising that runCommand
# permits arbitrary shell execution as root/SYSTEM.
resource "azurerm_role_definition" "vm_diagnostic_runner" {
  name        = "PathTriage Z8 VM Diagnostic Runner ${random_string.suffix.result}"
  scope       = local.rg_id
  description = "Allows running diagnostic commands on VMs (misleading name)"

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/virtualMachines/runCommand/action",
    ]
    not_actions = []
  }

  assignable_scopes = [
    local.rg_id
  ]
}

# Wait for role definition propagation
resource "time_sleep" "wait_for_role_definition" {
  depends_on      = [azurerm_role_definition.vm_diagnostic_runner]
  create_duration = "30s"
}

# Assign the custom role to MI-A, scoped to VM-B only.
# From MI-A's perspective, it has "diagnostic runner" access to one VM.
# From the attacker's perspective, it's root code execution on VM-B.
resource "azurerm_role_assignment" "mi_a_diagnostic_runner_on_vm_b" {
  scope              = azurerm_linux_virtual_machine.vm_b.id
  role_definition_id = azurerm_role_definition.vm_diagnostic_runner.role_definition_resource_id
  principal_id       = azurerm_linux_virtual_machine.vm_a.identity[0].principal_id

  depends_on = [time_sleep.wait_for_role_definition]
}
