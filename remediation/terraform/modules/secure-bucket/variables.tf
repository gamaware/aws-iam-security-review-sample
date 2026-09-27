variable "name" {
  description = "Globally unique bucket name."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer managed KMS key used for default encryption."
  type        = string
}

variable "access_log_bucket" {
  description = "Bucket that receives S3 server access logs."
  type        = string
}

variable "noncurrent_version_days" {
  description = "Days to keep noncurrent object versions."
  type        = number
  default     = 365
}
