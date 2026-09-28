# Findings S3-001, S3-002 and S3-003 in the report trace back here.

resource "aws_s3_bucket" "customer_exports" {
  bucket = "harborgoods-customer-exports"
}

resource "aws_s3_bucket_public_access_block" "customer_exports" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadForPartnerDownloads"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.customer_exports.arn}/*"
      },
      {
        Sid       = "AnalyticsVendorAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.partner_account_id}:root" }
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.customer_exports.arn, "${aws_s3_bucket.customer_exports.arn}/*"]
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.customer_exports]
}
