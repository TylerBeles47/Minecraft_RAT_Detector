variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "minecraft-rat-detector"
}

variable "cluster_name" {
  description = "ECS cluster name"
  type        = string
  default     = "minecraft-rat-detector"
}

variable "task_cpu" {
  description = "Task CPU units (1024 = 1 vCPU)"
  type        = string
  default     = "1024"
}

variable "task_memory" {
  description = "Task memory in MB"
  type        = string
  default     = "2048"
}

variable "desired_count" {
  description = "Number of tasks to run"
  type        = number
  default     = 1
}

variable "ecr_repository_url" {
  description = "ECR repository URL for the app image"
  type        = string
  default     = "104976232296.dkr.ecr.us-east-2.amazonaws.com/minecraft-rat-detector-app"
}

variable "database_secret_arn" {
  description = "ARN of the database secret in AWS Secrets Manager"
  type        = string
  default     = "arn:aws:secretsmanager:us-east-2:104976232296:secret:prod/appbeta/postgresql:DATABASE_URL::"
}

variable "s3_bucket_name" {
  description = "S3 bucket name for model storage"
  type        = string
  default     = "minecraft-rat-bucket"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b"]
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "minecraft-rat-detector"
    ManagedBy   = "terraform"
  }
}