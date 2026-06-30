terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

# subscription_id, tenant_id are read from ARM_SUBSCRIPTION_ID / ARM_TENANT_ID env
# (set per-shell after `az login`). Hard-coded UUIDs are kept out of the repo.
provider "azurerm" {
  features {}
  use_cli = true
}
