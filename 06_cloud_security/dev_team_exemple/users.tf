# ------------------------------
# Alice - Senior Developer + DBA
# ------------------------------
resource "aws_iam_user" "alice" {
  name = "alice.developer"
  tags = {
    Role = "Senior Developer + DBA"
  }
}

resource "aws_iam_user_group_membership" "alice_groups" {
  user = aws_iam_user.alice.name
  groups = [
    aws_iam_group.developers.name,
    aws_iam_group.database_admins.name
  ]
}

resource "aws_iam_user_login_profile" "alice" {
  user                    = aws_iam_user.alice.name
  password_reset_required = true
}

# ------------------------------
# Bob - Junior Developer
# ------------------------------
resource "aws_iam_user" "bob" {
  name = "bob.developer"
  tags = {
    Role = "Junior Developer"
  }
}

resource "aws_iam_user_group_membership" "bob_groups" {
  user = aws_iam_user.bob.name
  groups = [
    aws_iam_group.developers.name
  ]
}

resource "aws_iam_user_login_profile" "bob" {
  user                    = aws_iam_user.bob.name
  password_reset_required = true
}

# ------------------------------
# Charlie - DevOps
# ------------------------------
resource "aws_iam_user" "charlie" {
  name = "charlie.devops"
  tags = {
    Role = "DevOps Engineer"
  }
}

resource "aws_iam_user_group_membership" "charlie_groups" {
  user = aws_iam_user.charlie.name
  groups = [
    aws_iam_group.developers.name,
    aws_iam_group.deployment_team.name
  ]
}

resource "aws_iam_user_login_profile" "charlie" {
  user                    = aws_iam_user.charlie.name
  password_reset_required = true
}
