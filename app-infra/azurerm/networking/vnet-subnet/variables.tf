variable "vnet_name" {
  description = "The name of the virtual network."
  type        = string
}

variable "vnet_address_space" {
  description = "The address space that is used by the virtual network."
  type        = list(string)
}

variable "subnet_name" {
  description = "The name of the subnet for AKS."
  type        = string
}

variable "subnet_address_prefixes" {
  description = "The address prefixes to use for the subnet."
  type        = list(string)
}

variable "location" {
  description = "The Azure location where the resources will be created."
  type        = string
}

variable "resource_group_name" {
  description = "The name of the resource group in which to create the resources."
  type        = string
}

variable "tags" {
  description = "A map of tags to assign to the resources."
  type        = map(string)
  default     = {}
}
