# Multi-region trail with log file validation, KMS encryption, CloudWatch Logs delivery for
# alarms, and an encrypted SNS topic for delivery notifications.

locals {
  trail_name = "management-events"
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
}

module "trail_logs" {
  source            = "./modules/secure-bucket"
  name              = "harborgoods-trail-logs"
  kms_key_arn       = aws_kms_key.audit.arn
  access_log_bucket = aws_s3_bucket.access_logs.id
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = module.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [module.trail_logs.arn, "${module.trail_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = module.trail_logs.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${module.trail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${local.trail_name}"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.audit.arn
}

resource "aws_iam_role" "trail_to_logs" {
  name = "cloudtrail-to-cloudwatch-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    }]
  })
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name = "deliver-to-trail-log-group"
  role = aws_iam_role.trail_to_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:log-stream:*"
    }]
  })
}

resource "aws_sns_topic" "trail" {
  name              = "cloudtrail-delivery"
  kms_master_key_id = aws_kms_key.audit.id
}

resource "aws_sns_topic_policy" "trail" {
  arn = aws_sns_topic.trail.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CloudTrailPublishes"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.trail.arn
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    }]
  })
}

resource "aws_cloudtrail" "management_events" {
  name                          = local.trail_name
  s3_bucket_name                = module.trail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.audit.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_to_logs.arn
  sns_topic_name                = aws_sns_topic.trail.name

  depends_on = [aws_s3_bucket_policy.trail_logs, aws_sns_topic_policy.trail]
}
