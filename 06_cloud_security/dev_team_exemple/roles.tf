# ------------------------------
# Trust policy pour EC2
# ------------------------------
data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ------------------------------
# Role EC2-S3-Access
# ------------------------------
resource "aws_iam_role" "ec2_s3_access" {
  name               = "EC2-S3-Access"
  description        = "Role for EC2 instances to access S3 development buckets"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ec2_s3_access" {
  role       = aws_iam_role.ec2_s3_access.name
  policy_arn = aws_iam_policy.ec2_s3_access.arn
}

# Instance profile (necessaire pour attacher le role a une EC2)
resource "aws_iam_instance_profile" "ec2_s3_access" {
  name = "EC2-S3-Access-Profile"
  role = aws_iam_role.ec2_s3_access.name
}
