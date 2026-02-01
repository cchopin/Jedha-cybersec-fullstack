output "user_passwords" {
  description = "Mots de passe temporaires des utilisateurs"
  value = {
    alice   = aws_iam_user_login_profile.alice.password
    bob     = aws_iam_user_login_profile.bob.password
    charlie = aws_iam_user_login_profile.charlie.password
  }
  sensitive = true
}

output "console_login_url" {
  description = "URL de connexion a la console AWS"
  value       = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
}

data "aws_caller_identity" "current" {}

output "instance_profile_name" {
  description = "Nom du profil d'instance pour EC2"
  value       = aws_iam_instance_profile.ec2_s3_access.name
}
