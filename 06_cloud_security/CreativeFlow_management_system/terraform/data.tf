# =============================================================================
# CreativeFlow - Data Sources
# =============================================================================

# Recuperer le VPC par defaut
data "aws_vpc" "default" {
  default = true
}

# Recuperer l'AMI Amazon Linux 2023 la plus recente
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Detecter l'IP publique de l'admin (si non fournie)
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com"
}

locals {
  admin_ip    = var.admin_ip != "" ? var.admin_ip : trimspace(data.http.my_ip.response_body)
  bucket_name = "${var.project_name}-docs-${random_id.bucket_suffix.hex}"
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}
