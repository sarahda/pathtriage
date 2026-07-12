# =============================================================================
# PathTriage — Azure attack path Z5
# Key Vault Secret Escalation
#
# Class                : Credential discovery
# AWS analogue         : P7 (Lambda env-var theft), P8 (S3 credential harvest)
# MITRE ATT&CK (Cloud) : T1552.001 — Unsecured Credentials: Credentials In Files
#                        (extended to secure vault as discovery surface)
#
# Scenario:
#   The VM's System-Assigned MI is granted the built-in "Key Vault Secrets User"
#   role on a specific Key Vault. The Key Vault stores an elevated Service
#   Principal's client secret. The MI reads the secret via ARM/vault OAuth2
#   flow, uses the retrieved SP credentials to obtain an ARM token as the SP,
#   then exercises the SP's subscription-Contributor scope.
#
# Key design points:
#   - Uses the RBAC access model (Azure 2020+ recommended) rather than
#     legacy access policies. This matches the rest of the Azure catalogue
#     (Z2/Z3/Z4 all use RBAC) and aligns with AZ-500 curriculum.
#   - Elevated SP is pre-created via az CLI (D-Z2-01 pattern reused).
#     Not managed by Terraform.
#   - VM SKU is Standard_B1s — Key Vault operations are lightweight and
#     don't need D-series compute. Faster and cheaper provisioning.
#
# Why this is Z5 and not part of Z2:
#   Z2 exposes credentials in App Service app_settings (discoverable via
#   sites/config/list). Z5 exposes credentials in Key Vault (discoverable
#   via vault/secrets/get). Same primitive class (credential discovery)
#   but different discovery surfaces — hence different detection queries
#   in the defender-output module and different preventive controls.
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
# KEY VAULT — the credential storage surface
# =============================================================================

resource "azurerm_key_vault" "vault" {
  name                        = "ptz5kv${random_string.suffix.result}"
  location                    = local.location
  resource_group_name         = local.rg_name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  enable_rbac_authorization   = true
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  # Deployer needs temporary permission to write the initial secret.
  # Assigned below via azurerm_role_assignment.
}

# The deployer (whoever runs terraform apply) needs Key Vault Secrets Officer
# to write the initial secret. Real-world equivalent: a bootstrap step
# performed by an admin, not by the attacker.
resource "azurerm_role_assignment" "deployer_kv_secrets_officer" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Wait for role propagation before writing secret.
resource "time_sleep" "wait_for_deployer_role" {
  depends_on      = [azurerm_role_assignment.deployer_kv_secrets_officer]
  create_duration = "60s"
}

# Store the elevated SP's client secret in the vault.
resource "azurerm_key_vault_secret" "elevated_sp_secret" {
  name         = "pt-z5-elevated-sp-secret"
  value        = var.elevated_sp_client_secret
  key_vault_id = azurerm_key_vault.vault.id
  content_type = "application/json"

  # Store the SP app_id in tags so the exploit can retrieve it from the
  # secret's metadata (realistic pattern: apps store the SP identity alongside
  # the secret for use in OAuth2 flows).
  tags = {
    sp_app_id = var.elevated_sp_app_id
    purpose   = "cross-service-auth"
  }

  depends_on = [time_sleep.wait_for_deployer_role]
}

# =============================================================================
# FOOTHOLD VM — network + compute
# =============================================================================

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

# =============================================================================
# THE MISCONFIGURATION — VM MI granted read access to the secret
# =============================================================================

# "Key Vault Secrets User" — data plane, read-only on secrets.
# This is the standard "least privilege" role for apps that need to read
# secrets from a vault. The misconfiguration is not the role itself — it's
# that this vault contains a credential that grants far broader authority
# than the reading identity has.
resource "azurerm_role_assignment" "vm_mi_kv_secrets_user" {
  scope                = azurerm_key_vault.vault.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}
