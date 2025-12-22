variable "aws_region" {
  default = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "github_token" {
  description = "GitHub PAT for cloning repos"
  type        = string
  sensitive   = true
}

variable "environment" {
  default = "dev"
}

variable "project_name" {
  default = "security-remediation"
}

variable "vector_db_bucket_name" {
  description = "Name of the manual S3 bucket for vector DB"
}

variable "openai_api_key" {
  type      = string
  sensitive = true
}

variable "deepseek_api_key" {
  type      = string
  sensitive = true
}

variable "clerk_secret_key" {
  type      = string
  sensitive = true
}

variable "clerk_publishable_key" {
  type = string
}
