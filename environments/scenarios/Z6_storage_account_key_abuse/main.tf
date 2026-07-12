# =============================================================================
# PathTriage — Azure attack path Z6
# Storage Account Key Abuse (via tfstate credential harvest)
#
# Class                : Credential discovery
# AWS analogue         : P8 (S3 credential harvest via .tfstate objects)
# MITRE ATT&CK (Cloud) : T1552.001 — Unsecured Credentials: Credentials In Files
#                        T1550.001 — Use Alternate Authentication Material:
#                                    Application Access Token
#
# Scenario:
#   The VM's System-Assigned MI is granted the built-in
#   "Storage Account Key Operator Service Role" on a specific storage account.
#   That role permits calling `listKeys` on the storage account — returning
#   its shared access keys. The account has a private container that
#   holds a Terraform state file with embedded Service Principal
#   credentials (a common DevOps misconfiguration).
#
#   Exploit chain:
#     - MI acquires ARM token via IMDS
#     - Calls .../storageAccounts/{name}/listKeys → returns account key
#     - Uses account key to read blob via Azure Storage REST API
#     - Parses tfstate JSON, extracts embedded SP credentials
#     - Exchanges SP creds for ARM token (client_credentials grant)
#     - SP token holds Contributor at subscription scope → escalation
#
# Key design points:
#   - listKeys is the CONTROL-plane primitive (permits key retrieval).
#     Once the key is retrieved, all subsequent blob operations use the
#     DATA-plane shared-key authentication scheme, which bypasses AAD/RBAC.
#     This dual-plane characteristic is what makes storage account keys
#     particularly dangerous in Azure.
#   - Modern posture: disable account keys entirely (`allow_shared_key_access
#     = false`) and force AAD-only auth. Z6 uses the legacy config — account
#     keys enabled — because that IS the vulnerability being demonstrated.
#   - The blob content is a minimal tfstate-shaped JSON with embedded SP
#     credentials. Realistic tfstate files are hundreds of KB; a minimal
#     shape is sufficient to demonstrate the parsing exploit and keeps
#     the lab reproducible.
#
# Why this is Z6 and not part of Z5:
#   Z5 exposes credentials in Key Vault (intended secret storage).
#   Z6 exposes credentials in storage blobs (unintended — devops leak).
#   Different discovery surfaces, different preventive controls, different
#   detection queries. Same primitive class (credential discovery) — Azure
#   analogue of AWS P7/P8 split.
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
# STORAGE ACCOUNT — the discovery surface
# =============================================================================

resource "azurerm_storage_account" "sa" {
  name                     = "ptz6sa${random_string.suffix.result}"
  resource_group_name      = local.rg_name
  location                 = local.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # THE MISCONFIGURATION: shared-key access enabled.
  # Modern secure posture: allow_shared_key_access = false → forces AAD-only.
  # Z6 demonstrates the legacy pattern which is still widespread.
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true

  # Blob only — no queue/file/table needed for Z6
  blob_properties {
    versioning_enabled = false
  }
}

# Private container for the tfstate blob
resource "azurerm_storage_container" "tfstate" {
  name                  = "infrastructure"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

# Wait for storage account propagation before writing blob via the provider
# (which uses shared-key authentication internally).
resource "time_sleep" "wait_for_sa" {
  depends_on      = [azurerm_storage_account.sa, azurerm_storage_container.tfstate]
  create_duration = "30s"
}

# Terraform state blob with embedded SP credentials.
# Minimal tfstate-shaped JSON — realistic tfstate files are hundreds of KB
# but a compact shape is sufficient to demonstrate the parsing exploit
# and keeps the lab reproducible.
resource "azurerm_storage_blob" "tfstate" {
  name                   = "prod/terraform.tfstate"
  storage_account_name   = azurerm_storage_account.sa.name
  storage_container_name = azurerm_storage_container.tfstate.name
  type                   = "Block"
  content_type           = "application/json"

  source_content = jsonencode({
    version           = 4
    terraform_version = "1.5.7"
    serial            = 42
    lineage           = "12345678-1234-1234-1234-123456789abc"
    outputs           = {}
    resources = [
      {
        module    = "module.aad_apps"
        mode      = "managed"
        type      = "azuread_application"
        name      = "prod_service"
        provider  = "provider[\"registry.terraform.io/hashicorp/azuread\"]"
        instances = [
          {
            schema_version = 0
            attributes = {
              # Terraform stores these in plaintext in tfstate by default —
              # this is the well-documented "tfstate contains secrets"
              # problem: https://developer.hashicorp.com/terraform/language/state/sensitive-data
              application_id = var.elevated_sp_app_id
              client_secret  = var.elevated_sp_client_secret
              display_name   = "prod-service-principal"
            }
          }
        ]
      }
    ]
  })

  depends_on = [time_sleep.wait_for_sa]
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
  size                  = "Standard_D2s_v3"    # D-Z5 lesson: B1s unavailable
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
# THE MISCONFIGURATION — VM MI granted listKeys authority
# =============================================================================

# "Storage Account Key Operator Service Role" — the built-in role that grants
# Microsoft.Storage/storageAccounts/listkeys/action. This role is often granted
# to backup services, monitoring tools, or automation identities that need
# programmatic access to storage via SAS tokens.
#
# The subtle danger: this role gives NO data-plane read on the storage
# account (as visible in RBAC audits). But listKeys returns account keys,
# which by design grant FULL data-plane authority via shared-key auth.
# So a "least-privilege data reader" is actually a full data owner in
# disguise, if account keys are enabled.
resource "azurerm_role_assignment" "vm_mi_key_operator" {
  scope                = azurerm_storage_account.sa.id
  role_definition_name = "Storage Account Key Operator Service Role"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}
