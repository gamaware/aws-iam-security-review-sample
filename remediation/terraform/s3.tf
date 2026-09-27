# Buckets that hold customer or audit data use the secure-bucket module, so each Checkov
# finding is fixed once. The partner may list and read only its own prefix.

# Account-wide guardrail: no bucket in the account can be made public by policy or ACL.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "customer_exports" {
  source            = "./modules/secure-bucket"
  name              = "harborgoods-customer-exports"
  kms_key_arn       = aws_kms_key.exports.arn
  access_log_bucket = aws_s3_bucket.access_logs.id
}

resource "aws_s3_bucket_policy" "customer_exports" {
  bucket = module.customer_exports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [module.customer_exports.arn, "${module.customer_exports.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "PartnerListsItsPrefix"
        Effect    = "Allow"
        Principal = { AWS = var.partner_role_arn }
        Action    = "s3:ListBucket"
        Resource  = module.customer_exports.arn
        Condition = { StringLike = { "s3:prefix" = ["partner-a/*"] } }
      },
      {
        Sid       = "PartnerReadsItsPrefix"
        Effect    = "Allow"
        Principal = { AWS = var.partner_role_arn }
        Action    = "s3:GetObject"
        Resource  = "${module.customer_exports.arn}/partner-a/*"
      },
    ]
  })
}

# Target for server access logs. S3 does not deliver access logs to SSE-KMS buckets, and a
# log bucket that logs to itself loops, hence the skips.
resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This is the access log target; logging it to itself would loop.
  #checkov:skip=CKV_AWS_144:Single-region sample. Replication is planned work in the report.
  #checkov:skip=CKV_AWS_145:S3 server access log delivery requires SSE-S3 on the target bucket.
  bucket = "harborgoods-access-logs"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 server access log delivery requires SSE-S3 on the target bucket (same reason as CKV_AWS_145).
#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 400
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "access_logs" {
  bucket      = aws_s3_bucket.access_logs.id
  eventbridge = true
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "S3ServerAccessLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/*"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}
