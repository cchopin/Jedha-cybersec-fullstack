# =============================================================================
# CreativeFlow - S3 Bucket
# =============================================================================

resource "aws_s3_bucket" "docs" {
  bucket = local.bucket_name

  tags = {
    Project     = "CreativeFlow"
    Environment = "Production"
  }
}

# Activer le versioning
resource "aws_s3_bucket_versioning" "docs" {
  bucket = aws_s3_bucket.docs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Bloquer tout acces public
resource "aws_s3_bucket_public_access_block" "docs" {
  bucket = aws_s3_bucket.docs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Politique du bucket : forcer HTTPS uniquement
resource "aws_s3_bucket_policy" "docs" {
  bucket = aws_s3_bucket.docs.id

  # Attendre que le block public access soit en place
  depends_on = [aws_s3_bucket_public_access_block.docs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceSSLOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.docs.arn,
          "${aws_s3_bucket.docs.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# Creer la structure de dossiers
resource "aws_s3_object" "uploads_drafts" {
  bucket  = aws_s3_bucket.docs.id
  key     = "uploads/drafts/"
  content = ""
}

resource "aws_s3_object" "uploads_final" {
  bucket  = aws_s3_bucket.docs.id
  key     = "uploads/final/"
  content = ""
}

resource "aws_s3_object" "uploads_client_assets" {
  bucket  = aws_s3_bucket.docs.id
  key     = "uploads/client-assets/"
  content = ""
}

resource "aws_s3_object" "app_logs" {
  bucket  = aws_s3_bucket.docs.id
  key     = "app-logs/"
  content = ""
}
