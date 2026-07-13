# =============================================================================
# PathTriage — Azure attack path Z7
# Managed Identity / Service Principal Chain (via OBO delegated impersonation)
#
# Class                : Trust topology
# AWS analogue         : P4 (AssumeRole Chain)
# MITRE ATT&CK (Cloud) : T1550.001 — Use Alternate Authentication Material:
#                                    Application Access Token
#                        T1078.004 — Valid Accounts: Cloud Accounts
#
# Scenario:
#   A VM has SP-A credentials embedded in a local file. SP-A holds only
#   Reader at subscription scope. But SP-A has been granted delegated
#   permission to access SP-B (via Azure AD OAuth2 delegated permission
#   consent — 'user_impersonation' scope on SP-B's API).
#
#   SP-B holds Contributor at subscription scope. Using the OBO (On-Behalf-Of)
#   token exchange flow, SP-A can obtain a token that represents SP-B, then
#   act with SP-B's authority. The attacker never held SP-B's credentials;
#   the escalation happens entirely via the delegated permission grant.
#
# Attack Chain:
#   1. Attacker with SSH access to VM reads embedded SP-A credentials
#   2. SP-A obtains initial token (client_credentials, scope=SP-A/.default)
#   3. OBO token exchange:
#        - grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
#        - assertion=<SP-A initial token>
#        - scope=api://SP-B-appid/.default (OR management.azure.com/.default)
#        - requested_token_use=on_behalf_of
#      Result: SP-B ARM token
#   4. SP-B token used to PATCH tag on RG — succeeds via SP-B's Contributor
#
# Why this is distinct from Z2/Z5/Z6:
#   Z2/Z5/Z6 all end at "SP credentials extracted → SP token acquired via
#   client_credentials". Z7 exercises a fundamentally different mechanism:
#   OBO token exchange without possessing SP-B's credentials at all.
#   The attacker exploits a DELEGATED PERMISSION GRANT — a Trust relationship
#   configured at Azure AD level between SP-A and SP-B.
#
# AWS-vs-Azure comparative finding:
#   AWS P4 (AssumeRole Chain) is SESSION-level — each hop creates a new STS
#   session with new credentials, visible in CloudTrail as a sequence of
#   AssumeRole events. Azure OBO is AUTHORIZATION-level — the delegated
#   permission grant is a persistent configuration (in AAD), and the token
#   exchange is a single event that returns a new token immediately.
#   Detection surfaces differ substantially:
#     - AWS: correlate 3+ AssumeRole events with same principal chain
#     - Azure: correlate delegated permission grant (rare event, in Audit
#              logs) + subsequent OBO token acquisitions (SignInLogs with
#              CorrelationId across events)
#   This is the largest structural asymmetry among all 8 Azure paths.
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
# FOOTHOLD VM — network + compute + SP-A credentials embedded
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

# VM: SP-A credentials embedded in cloud-init.
# In real-world attacks, credentials are often found in application config,
# environment variables, or leaked to disk by CI/CD pipelines.
resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "${var.name_prefix}-vm"
  resource_group_name   = local.rg_name
  location              = local.location
  size                  = "Standard_D2s_v3"
  admin_username        = var.vm_admin_username
  network_interface_ids = [azurerm_network_interface.vm.id]

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

  # SP-A credentials embedded in a config file — realistic pattern for
  # applications that use SP creds instead of Managed Identity.
  custom_data = base64encode(<<-CLOUDINIT
    #cloud-config
    package_update: true
    packages:
      - python3-pip
    runcmd:
      - pip3 install --quiet requests
    write_files:
      - path: /home/${var.vm_admin_username}/app_config.json
        owner: ${var.vm_admin_username}:${var.vm_admin_username}
        permissions: '0600'
        content: |
          {
            "sp_a_app_id":        "${var.sp_a_app_id}",
            "sp_a_client_secret": "${var.sp_a_client_secret}",
            "sp_b_app_id":        "${var.sp_b_app_id}",
            "tenant_id":          "${var.tenant_id}",
            "purpose":            "cross-service-auth"
          }
  CLOUDINIT
  )
}
