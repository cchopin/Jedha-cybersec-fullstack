# ------------------------------
# Groupe Developers
# ------------------------------
resource "aws_iam_group" "developers" {
  name = "Developers"
}

resource "aws_iam_group_policy_attachment" "developers_policy" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.developer.arn
}

resource "aws_iam_group_policy_attachment" "developers_iam_readonly" {
  group      = aws_iam_group.developers.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

# ------------------------------
# Groupe DatabaseAdmins
# ------------------------------
resource "aws_iam_group" "database_admins" {
  name = "DatabaseAdmins"
}

resource "aws_iam_group_policy_attachment" "dbadmins_database_policy" {
  group      = aws_iam_group.database_admins.name
  policy_arn = aws_iam_policy.database.arn
}

resource "aws_iam_group_policy_attachment" "dbadmins_developer_policy" {
  group      = aws_iam_group.database_admins.name
  policy_arn = aws_iam_policy.developer.arn
}

resource "aws_iam_group_policy_attachment" "dbadmins_iam_readonly" {
  group      = aws_iam_group.database_admins.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

# ------------------------------
# Groupe DeploymentTeam
# ------------------------------
resource "aws_iam_group" "deployment_team" {
  name = "DeploymentTeam"
}

resource "aws_iam_group_policy_attachment" "deployment_policy" {
  group      = aws_iam_group.deployment_team.name
  policy_arn = aws_iam_policy.deployment.arn
}

resource "aws_iam_group_policy_attachment" "deployment_developer_policy" {
  group      = aws_iam_group.deployment_team.name
  policy_arn = aws_iam_policy.developer.arn
}

resource "aws_iam_group_policy_attachment" "deployment_iam_readonly" {
  group      = aws_iam_group.deployment_team.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}
