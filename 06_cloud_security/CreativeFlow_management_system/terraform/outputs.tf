# =============================================================================
# CreativeFlow - Outputs
# =============================================================================

output "app_url" {
  description = "URL de l'application CreativeFlow"
  value       = "http://${aws_instance.webapp.public_ip}:5000"
}

output "instance_public_ip" {
  description = "IP publique de l'instance EC2"
  value       = aws_instance.webapp.public_ip
}

output "instance_id" {
  description = "ID de l'instance EC2"
  value       = aws_instance.webapp.id
}

output "ssh_command" {
  description = "Commande SSH pour se connecter"
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ec2-user@${aws_instance.webapp.public_ip}"
}

output "s3_bucket_name" {
  description = "Nom du bucket S3"
  value       = aws_s3_bucket.docs.id
}

output "iam_role_used" {
  description = "Role IAM attache a l'instance"
  value       = "CreativeFlow-${var.iam_role}"
}

output "security_group_id" {
  description = "ID du Security Group"
  value       = aws_security_group.webapp.id
}

output "admin_ip_detected" {
  description = "IP admin utilisee pour SSH"
  value       = local.admin_ip
}
