# ------------------------------
# DeveloperPolicy
# ------------------------------
resource "aws_iam_policy" "developer" {
  name        = "DeveloperPolicy"
  description = "Policy granting development team access to development resources"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2DevelopmentAccess"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StopInstances",
          "ec2:StartInstances"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:InstanceType" = ["t2.micro", "t2.small", "t3.micro", "t3.small"]
          }
        }
      },
      {
        Sid    = "S3DevelopmentAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = ["arn:aws:s3:::dev-*", "arn:aws:s3:::dev-*/*"]
      },
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:log-group:dev-*"
      },
      {
        Sid    = "LambdaDevelopmentAccess"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:DeleteFunction",
          "lambda:GetFunction",
          "lambda:ListFunctions",
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:*:*:function:dev-*"
      }
    ]
  })
}

# ------------------------------
# DatabasePolicy
# ------------------------------
resource "aws_iam_policy" "database" {
  name        = "DatabasePolicy"
  description = "Policy for database administrators managing development databases"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RDSManagement"
        Effect = "Allow"
        Action = [
          "rds:CreateDBInstance",
          "rds:DeleteDBInstance",
          "rds:DescribeDBInstances",
          "rds:ModifyDBInstance",
          "rds:RebootDBInstance",
          "rds:StartDBInstance",
          "rds:StopDBInstance",
          "rds:CreateDBSnapshot",
          "rds:DeleteDBSnapshot",
          "rds:DescribeDBSnapshots",
          "rds:RestoreDBInstanceFromDBSnapshot"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "rds:db-tag/Environment" = "dev*"
          }
        }
      },
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:CreateTable",
          "dynamodb:DeleteTable",
          "dynamodb:DescribeTable",
          "dynamodb:UpdateTable",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/dev-*"
      },
      {
        Sid    = "BackupAccess"
        Effect = "Allow"
        Action = [
          "backup:CreateBackupPlan",
          "backup:CreateBackupSelection",
          "backup:StartBackupJob",
          "backup:DescribeBackupJob",
          "backup:ListBackupJobs"
        ]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------
# DeploymentPolicy
# ------------------------------
resource "aws_iam_policy" "deployment" {
  name        = "DeploymentPolicy"
  description = "Policy for deployment team"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CodeDeployAccess"
        Effect = "Allow"
        Action = [
          "codedeploy:CreateApplication",
          "codedeploy:CreateDeployment",
          "codedeploy:CreateDeploymentGroup",
          "codedeploy:GetApplication",
          "codedeploy:GetDeployment",
          "codedeploy:ListApplications",
          "codedeploy:ListDeployments"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRAccess"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSAccess"
        Effect = "Allow"
        Action = [
          "ecs:UpdateService",
          "ecs:DescribeServices",
          "ecs:DescribeTasks",
          "ecs:ListTasks",
          "ecs:RunTask",
          "ecs:StopTask"
        ]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------
# EC2S3AccessPolicy (pour le role)
# ------------------------------
resource "aws_iam_policy" "ec2_s3_access" {
  name        = "EC2S3AccessPolicy"
  description = "Policy for EC2 instances to access S3 development buckets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:CreateBucket",
          "s3:DeleteBucket"
        ]
        Resource = [
          "arn:aws:s3:::dev-*",
          "arn:aws:s3:::dev-*/*"
        ]
      }
    ]
  })
}
