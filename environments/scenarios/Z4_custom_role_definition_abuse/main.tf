# =============================================================================
# PathTriage — Azure attack path Z4
# Custom role definition abuse (mutate-role primitive)
#
# Class                : IAM modification
# AWS analogue         : P3 (CreatePolicyVersion)
# MITRE ATT&CK (Cloud) : T1098 — Account Manipulation
#
# Scenario:
#   The VM's System-Assigned MI is granted built-in User Access Administrator
#   on the resource group, plus a custom "App Operator" role (read-only over
#   VMs / Web Apps) at the same scope. The MI uses UAA's
#   Microsoft.Authorization/roleDefinitions/write capability to mutate the
#   App Operator role definition — injecting wildcard "*" into its Actions[]
#   so every assignee silently becomes Owner-equivalent. RBAC audit on role
#   *assignments* shows zero change; the modification is on the role
#   *definition* itself, retroactively elevating all assignees.
#
# Why UAA and not a custom role with roleDefinitions/write?
#   See D-Z4-02 in the README. Azure silently refuses to enforce
#   Microsoft.Authorization/* actions when they appear in a custom role's
#   permissions[].actions array; only built-in User Access Administrator
#   and Owner can actually exercise these actions. This was discovered
#   experimentally during initial Z4 verification (HTTP 403
#   AuthorizationFailed despite the action being present in the custom
#   role's definition).
#
# Z3 vs Z4 distinction:
#   Z3 starting role = UAA. Primitive exercised = roleAssignments/write
#                     (new assignment binding existing identity to higher role).
#   Z4 starting role = UAA. Primitive exercised = roleDefinitions/write
#                     (mutation of existing role; silent, retroactive).
#   Same starting privilege, two different primitives, two different
#   detection signals — supports the "primitive-not-per-path" thesis of
#   the W8 defender-output module.
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

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

# -----------------------------------------------------------------------------
# CUSTOM ROLE — "App Operator" (the role to be MUTATED)
# Innocuous read-only access to VMs and Web Apps.
# After exploit: its Actions[] will contain "*", silently making every
# assignee Owner-equivalent.
# -----------------------------------------------------------------------------
resource "azurerm_role_definition" "app_operator" {
  name        = "pt-z4-app-operator-${random_string.suffix.result}"
  scope       = local.rg_id
  description = "Read-only access to VMs and Web Apps (PathTriage Z4)"

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Web/sites/read",
      "Microsoft.Web/serverFarms/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
    ]
    not_actions = []
  }

  assignable_scopes = [local.rg_id]
}

resource "azurerm_role_assignment" "vm_mi_app_operator" {
  scope              = local.rg_id
  role_definition_id = azurerm_role_definition.app_operator.role_definition_resource_id
  principal_id       = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

# -----------------------------------------------------------------------------
# THE MISCONFIGURATION — built-in User Access Administrator on RG.
# (See D-Z4-02: custom roles cannot exercise Microsoft.Authorization/*
# actions, only built-in UAA / Owner can.)
# Z3 used the same starting role to exercise roleAssignments/write; Z4
# uses it to exercise roleDefinitions/write — different primitive,
# different detection signal, same starting privilege.
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "vm_mi_owner" {
  scope                = "/subscriptions/${data.azurerm_subscription.current.subscription_id}"
  role_definition_name = "Owner"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}
