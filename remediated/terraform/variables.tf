variable "region" {
  description = "Home region of the fictional account."
  type        = string
  default     = "us-east-1"
}

variable "github_repository" {
  description = "The one GitHub repository (owner/name) whose production environment may deploy."
  type        = string
  default     = "examplecorp/reporting-app"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "Use owner/name with no wildcards."
  }
}

variable "partner_role_arn" {
  description = "Role in the approved analytics partner account that reads its export prefix. Placeholder ID."
  type        = string
  default     = "arn:aws:iam::111122223333:role/partner-ingest"
}

variable "release_bucket_name" {
  description = "Existing bucket for release artifacts, owned by the application stack."
  type        = string
  default     = "examplecorp-release-artifacts"
}

variable "lambda_function_name" {
  description = "The one function the CI role may update."
  type        = string
  default     = "reporting-app"
}
