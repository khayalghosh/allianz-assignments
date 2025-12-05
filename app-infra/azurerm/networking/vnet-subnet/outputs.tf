output "vnet_id" {
  description = "The ID of the virtual network."
  value       = azurerm_virtual_network.virtual_network.id
}

output "subnet_id" {
  description = "The ID of the AKS subnet."
  value       = azurerm_subnet.aks_subnet.id
}

output "subnet_name" {
  description = "The name of the AKS subnet."
  value       = azurerm_subnet.aks_subnet.name
}
