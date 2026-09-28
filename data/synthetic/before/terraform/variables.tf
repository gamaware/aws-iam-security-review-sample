variable "region" {
  description = "Home region of the fictional account."
  type        = string
  default     = "us-east-1"
}

variable "github_org" {
  description = "GitHub organization allowed to assume the CI role."
  type        = string
  default     = "harborgoods"
}

variable "partner_account_id" {
  description = "Analytics vendor account granted access to customer exports. Placeholder ID."
  type        = string
  default     = "999988887777"
}
