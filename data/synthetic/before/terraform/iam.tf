# Findings IAM-001, IAM-002, IAM-004, IAM-005, IAM-006 and IAM-009 in the report trace back here.

data "aws_caller_identity" "current" {}

resource "aws_iam_user" "deploy_bot" {
  name = "deploy-bot"
}

# A long-lived key for a pipeline. The secret lands in state and in the CI secret store.
resource "aws_iam_access_key" "deploy_bot" {
  user = aws_iam_user.deploy_bot.name
}

resource "aws_iam_user_policy" "deploy_bot" {
  name = "deploy-bot-s3"
  user = aws_iam_user.deploy_bot.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReleaseUploads"
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "admins" {
  name = "Admins"
}

resource "aws_iam_group_policy_attachment" "admins" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_group" "platform_ops" {
  name = "PlatformOps"
}

resource "aws_iam_policy" "platform_ops" {
  name = "platform-ops"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ManageAppRoles"
        Effect   = "Allow"
        Action   = ["iam:*"]
        Resource = "*"
      },
      {
        Sid      = "PassAnyRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      },
      {
        Sid      = "InstanceLifecycle"
        Effect   = "Allow"
        Action   = ["ec2:StopInstances", "ec2:TerminateInstances", "ec2:Describe*"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_group_policy_attachment" "platform_ops" {
  group      = aws_iam_group.platform_ops.name
  policy_arn = aws_iam_policy.platform_ops.arn
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "ci_deploy" {
  name = "ci-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci_deploy" {
  name = "ci-deploy-inline"
  role = aws_iam_role.ci_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "TemporaryFullAccessForPipeline"
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
