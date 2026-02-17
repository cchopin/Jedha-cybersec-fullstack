# =============================================================================
# CreativeFlow - Variables Terraform
# =============================================================================

variable "aws_region" {
  description = "Region AWS pour le deploiement"
  type        = string
  default     = "eu-west-3"
}

variable "project_name" {
  description = "Nom du projet (utilise pour le nommage des ressources)"
  type        = string
  default     = "creativeflow"
}

variable "instance_type" {
  description = "Type d'instance EC2"
  type        = string
  default     = "t2.micro"
}

variable "key_name" {
  description = "Nom de la key pair SSH (doit exister dans AWS)"
  type        = string
}

variable "iam_role" {
  description = "Role IAM a attacher a l'instance EC2 (Developer ou Contributor)"
  type        = string
  default     = "Developer"

  validation {
    condition     = contains(["Developer", "Contributor"], var.iam_role)
    error_message = "Le role doit etre 'Developer' ou 'Contributor'."
  }
}

variable "admin_ip" {
  description = "Votre IP publique pour l'acces SSH (format: x.x.x.x). Laisser vide pour detection automatique."
  type        = string
  default     = ""
}
