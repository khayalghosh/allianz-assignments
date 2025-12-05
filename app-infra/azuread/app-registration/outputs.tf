
output "application_id" {
  description = "The Application (client) ID for the Azure AD application"
  value       = azuread_application.app.application_id
}

output "application_object_id" {
  description = "The Application object ID"
  value       = azuread_application.app.object_id
}

output "service_principal_id" {
  description = "The Service Principal object ID"
  value       = azuread_service_principal.sp.object_id
}

output "client_secret_value" {
  description = "The client secret value (sensitive)"
  value       = azuread_application_password.client_secret.value
  sensitive   = true
}
