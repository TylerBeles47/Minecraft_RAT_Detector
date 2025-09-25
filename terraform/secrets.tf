# Create a new secret with DATABASE_URL format for application compatibility
resource "aws_secretsmanager_secret" "database_url" {
  name        = "minecraft-rat-detector/database"
  description = "Database URL for Minecraft RAT Detector application"

  tags = var.tags
}

# Get RDS credentials to construct DATABASE_URL
data "aws_secretsmanager_secret_version" "rds_creds" {
  secret_id = aws_db_instance.main.master_user_secret[0].secret_arn
}

locals {
  rds_creds = jsondecode(data.aws_secretsmanager_secret_version.rds_creds.secret_string)
  database_url = "postgresql://${local.rds_creds.username}:${local.rds_creds.password}@${split(":", aws_db_instance.main.endpoint)[0]}:${aws_db_instance.main.port}/${aws_db_instance.main.db_name}"
}

# Store the constructed DATABASE_URL in the application secret
resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = jsonencode({
    DATABASE_URL = local.database_url
  })
}