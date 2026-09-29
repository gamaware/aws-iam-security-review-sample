# Scoped policy rewrites. The same documents live in ../policies/ as JSON, which is what
# scripts/iam_review.py reads; tests/test_consistency.py keeps the statements in step.

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# People get access through IAM Identity Center. The only IAM group left is for the
# on-call engineers, and it carries the deny-without-MFA guardrail below.
resource "aws_iam_group" "platform_ops" {
  name = "PlatformOps"
}

resource "aws_iam_policy" "platform_ops" {
  name = "platform-ops"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListRoles"
        Effect   = "Allow"
        Action   = "iam:ListRoles"
        Resource = "*"
      },
      {
        Sid      = "ReadRolesForTroubleshooting"
        Effect   = "Allow"
        Action   = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"]
        Resource = "arn:aws:iam::${local.account_id}:role/*"
      },
      {
        Sid    = "PassOnlyAppRolesToEc2WithMfa"
        Effect = "Allow"
        # PassRole is the point of this statement (F-05): limited to app-* roles, EC2 and MFA.
        # nosemgrep: terraform.lang.security.iam.no-iam-resource-exposure.no-iam-resource-exposure
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${local.account_id}:role/app-*"
        Condition = {
          StringEquals = { "iam:PassedToService" = "ec2.amazonaws.com" }
          Bool         = { "aws:MultiFactorAuthPresent" = "true" }
        }
      },
      {
        Sid      = "DescribeInstances"
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeTags"]
        Resource = "*"
      },
      {
        Sid       = "StopAndTerminatePlatformInstancesOnly"
        Effect    = "Allow"
        Action    = ["ec2:StopInstances", "ec2:TerminateInstances"]
        Resource  = "arn:aws:ec2:*:${local.account_id}:instance/*"
        Condition = { StringEquals = { "aws:ResourceTag/team" = "platform" } }
      },
    ]
  })
}

# The deny-without-MFA guardrail and the MFA self-enrollment it leaves open live in one
# document, as in AWS's self-manage-MFA example policy: any group that gets the guardrail can
# also enroll, and the Deny's NotAction list sits next to the actions it exempts (ADR 0006).
resource "aws_iam_policy" "require_mfa" {
  name = "require-mfa"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Lets a new or re-enrolling engineer set up MFA on their own user only.
        Sid    = "ManageOwnMfaDevice"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice",
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:mfa/$${aws:username}",
          "arn:aws:iam::${local.account_id}:user/$${aws:username}",
        ]
      },
      {
        # The console's Security credentials page lists virtual MFA devices before it can
        # assign one. The action does not support resource-level permissions, so it stays on
        # "*" in its own statement, as in AWS's self-manage-credentials example policy.
        Sid      = "ListVirtualMfaDevices"
        Effect   = "Allow"
        Action   = "iam:ListVirtualMFADevices"
        Resource = "*"
      },
      {
        Sid    = "DenyEverythingExceptMfaSetupWithoutMfa"
        Effect = "Deny"
        NotAction = [
          "iam:ChangePassword",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken",
        ]
        Resource  = "*"
        Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
      },
    ]
  })
}

resource "aws_iam_group_policy_attachment" "platform_ops" {
  for_each = {
    platform_ops = aws_iam_policy.platform_ops.arn
    require_mfa  = aws_iam_policy.require_mfa.arn
  }
  group      = aws_iam_group.platform_ops.name
  policy_arn = each.value
}

# CI uses GitHub OIDC: no IAM user, no stored key, one repository, one environment.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "ci_deploy" {
  name                 = "ci-deploy"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "GitHubProductionEnvironmentOnly"
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repository}:environment:production"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci_deploy" {
  name = "ci-deploy"
  role = aws_iam_role.ci_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ListReleasePrefix"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = "arn:aws:s3:::${var.release_bucket_name}"
        Condition = { StringLike = { "s3:prefix" = ["reporting-app/*"] } }
      },
      {
        Sid      = "UploadReleaseArtifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::${var.release_bucket_name}/reporting-app/*"
      },
      {
        Sid    = "DeployOneFunction"
        Effect = "Allow"
        # Accepted risk: new code runs with this one function's execution role (outside this review).
        # The CI role has no iam:PassRole, so it cannot give the function a different role.
        # nosemgrep: terraform.lang.security.iam.no-iam-priv-esc-roles.no-iam-priv-esc-roles
        Action   = ["lambda:GetFunction", "lambda:UpdateFunctionCode", "lambda:PublishVersion"]
        Resource = "arn:aws:lambda:${var.region}:${local.account_id}:function:${var.lambda_function_name}"
      },
    ]
  })
}
