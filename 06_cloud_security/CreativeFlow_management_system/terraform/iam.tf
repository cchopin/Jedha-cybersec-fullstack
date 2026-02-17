# =============================================================================
# CreativeFlow - IAM Roles & Policies
# =============================================================================

# ---------------------------------------------------------------------------
# Trust Policy (commune aux deux roles) : permet a EC2 d'assumer le role
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# =============================================================================
# ROLE DEVELOPER
# =============================================================================

resource "aws_iam_role" "developer" {
  name               = "CreativeFlow-Developer"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json

  tags = {
    Project     = "CreativeFlow"
    Environment = "Production"
  }
}

data "aws_iam_policy_document" "developer" {
  # S3 : acces complet aux buckets creativeflow-docs-*
  statement {
    sid = "S3FullAccessToCreativeFlowBucket"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetObjectVersion",
      "s3:GetBucketVersioning",
    ]
    resources = [
      "arn:aws:s3:::creativeflow-docs-*",
      "arn:aws:s3:::creativeflow-docs-*/*",
    ]
  }

  # S3 : lister tous les buckets
  statement {
    sid = "S3ListAllBuckets"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
    ]
    resources = ["*"]
  }

  # EC2 : lecture seule pour troubleshooting
  statement {
    sid = "EC2DescribeForTroubleshooting"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeVolumes",
    ]
    resources = ["*"]
  }

  # CloudWatch Logs
  statement {
    sid = "CloudWatchLogsAccess"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:*:*:log-group:/creativeflow/*",
      "arn:aws:logs:*:*:log-group:/creativeflow/*:*",
    ]
  }

  # STS : identifier le role actuel
  statement {
    sid       = "STSGetCallerIdentity"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "developer" {
  name   = "CreativeFlow-Developer-Policy"
  role   = aws_iam_role.developer.id
  policy = data.aws_iam_policy_document.developer.json
}

resource "aws_iam_instance_profile" "developer" {
  name = "CreativeFlow-Developer"
  role = aws_iam_role.developer.name
}

# =============================================================================
# ROLE CONTRIBUTOR
# =============================================================================

resource "aws_iam_role" "contributor" {
  name               = "CreativeFlow-Contributor"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json

  tags = {
    Project     = "CreativeFlow"
    Environment = "Production"
  }
}

data "aws_iam_policy_document" "contributor" {
  # S3 : lister uniquement le dossier uploads/
  statement {
    sid       = "S3ListUploadsFolder"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::creativeflow-docs-*"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        "uploads/*",
        "uploads/drafts/*",
        "uploads/final/*",
        "uploads/client-assets/*",
      ]
    }
  }

  # S3 : upload/download dans les dossiers autorises
  statement {
    sid = "S3UploadToDesignatedFolders"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::creativeflow-docs-*/uploads/drafts/*",
      "arn:aws:s3:::creativeflow-docs-*/uploads/final/*",
      "arn:aws:s3:::creativeflow-docs-*/uploads/client-assets/*",
    ]
  }

  # DENY : acces aux logs applicatifs
  statement {
    sid    = "DenyAppLogsAccess"
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::creativeflow-docs-*/app-logs/*",
    ]
  }

  # DENY : suppression d'objets
  statement {
    sid       = "DenyDeleteOperations"
    effect    = "Deny"
    actions   = ["s3:DeleteObject"]
    resources = ["arn:aws:s3:::creativeflow-docs-*/*"]
  }

  # STS : identifier le role actuel
  statement {
    sid       = "STSGetCallerIdentity"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "contributor" {
  name   = "CreativeFlow-Contributor-Policy"
  role   = aws_iam_role.contributor.id
  policy = data.aws_iam_policy_document.contributor.json
}

resource "aws_iam_instance_profile" "contributor" {
  name = "CreativeFlow-Contributor"
  role = aws_iam_role.contributor.name
}
