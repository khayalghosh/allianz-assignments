
terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.30"
    }
  }
}

provider "azuread" {}

data "azuread_client_config" "current" {}

locals {
  effective_owners = length(var.owners) > 0 ? var.owners : [data.azuread_client_config.current.object_id]
}

resource "azuread_application" "app" {
  display_name = var.app_name

  owners = local.effective_owners

  web {
    redirect_uris = var.redirect_uris
  }

  # Only include the required_resource_access block when an app id was provided
  dynamic "required_resource_access" {
    for_each = var.required_resource_access_app_id != "" ? [1] : []
    content {
      resource_app_id = var.required_resource_access_app_id

      resource_access {
        id   = var.required_resource_access_id
        type = var.required_resource_access_type
      }
    }
  }
}

resource "azuread_service_principal" "sp" {
  application_id = azuread_application.app.application_id
}

resource "azuread_application_password" "client_secret" {
  application_object_id = azuread_application.app.object_id
  display_name   = "${var.app_name}-client-secret"
  # Use an explicit ISO-8601 end date if provided, otherwise leave nil to use provider default
  end_date = var.client_secret_end_date != "" ? var.client_secret_end_date : null
}
