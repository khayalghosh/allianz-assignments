
variable "required_resource_access_type" {
  description = "Optional type inside resource_access (Scope|Role)"
  type        = string
  default     = ""
}

variable "app_name" {
  description = "Display name for the Azure AD application"
  type        = string
  default     = "allianz-app"
}

variable "owners" {
  description = "List of owners (object IDs or user principal names). Optional."
  type        = list(string)
  default     = []
}

variable "redirect_uris" {
  description = "List of redirect URIs for a web application"
  type        = list(string)
  default     = []
}

variable "required_resource_access_app_id" {
  description = "Optional resource app id for required_resource_access block"
  type        = string
  default     = ""
}

variable "required_resource_access_id" {
  description = "Optional id inside resource_access"
  type        = string
  default     = ""
}

variable "client_secret_end_date" {
  description = "Optional explicit end date for the client secret in RFC3339 format (e.g. 2026-12-04T00:00:00Z). Leave empty to use provider default."
  type        = string
  default     = ""
}
