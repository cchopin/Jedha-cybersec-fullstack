# =============================================================================
# CreativeFlow - Security Group
# =============================================================================

resource "aws_security_group" "webapp" {
  name        = "creativeflow-webapp-sg"
  description = "Security Group pour CreativeFlow webapp"
  vpc_id      = data.aws_vpc.default.id

  # SSH - restreint a l'IP de l'admin
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${local.admin_ip}/32"]
  }

  # Flask app - port 5000
  ingress {
    description = "Flask App"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Tout le trafic sortant
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "creativeflow-webapp-sg"
    Project     = "CreativeFlow"
    Environment = "Production"
  }
}
