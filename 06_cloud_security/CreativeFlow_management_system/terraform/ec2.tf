# =============================================================================
# CreativeFlow - Instance EC2
# =============================================================================

resource "aws_instance" "webapp" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.webapp.id]

  # Choisir le profil IAM selon la variable iam_role
  iam_instance_profile = var.iam_role == "Developer" ? aws_iam_instance_profile.developer.name : aws_iam_instance_profile.contributor.name

  # Script de demarrage qui installe et lance l'application
  user_data = templatefile("${path.module}/user-data.sh", {
    s3_bucket_name = aws_s3_bucket.docs.id
    aws_region     = var.aws_region
  })

  tags = {
    Name        = "CreativeFlow-WebApp"
    Project     = "CreativeFlow"
    Role        = "CreativeFlow-${var.iam_role}"
    Environment = "Production"
  }
}
