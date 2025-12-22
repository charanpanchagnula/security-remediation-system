variable "environment" {
  type = string
}

variable "project_name" {
  type = string
}

variable "ecr_image_uri" {
  type = string
}

variable "instance_role_arn" {
  type = string
}

variable "access_role_arn" {
  type = string
}

variable "sqs_queue_url" {
  type = string
}

variable "artifacts_bucket_name" {
  type = string
}

variable "results_bucket_name" {
  type = string
}

variable "vector_db_bucket_name" {
  type = string
}

# Secrets (Passed via tfvars or ENV)
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

variable "github_token" {
  type      = string
  sensitive = true
}

resource "aws_apprunner_service" "service" {
  service_name = "${var.project_name}-service-${var.environment}"

  source_configuration {
    image_repository {
      image_identifier      = var.ecr_image_uri
      image_repository_type = "ECR"
      image_configuration {
        port = "8000"
        runtime_environment_variables = {
          APP_ENV                        = "production"
          SQS_QUEUE_URL                  = var.sqs_queue_url
          S3_SOURCE_BUCKET_NAME          = var.artifacts_bucket_name
          S3_RESULTS_BUCKET_NAME         = var.results_bucket_name
          S3_VECTOR_BUCKET_NAME          = var.vector_db_bucket_name
          # S3 Vector Bucket is handled via manual bucket logic in code?
          # Actually, code uses hardcoded path or similar? 
          # No, we need to pass the bucket name if the code supports it.
          # Wait, store.py uses "vector_db/lancedb" prefix in the bucket returned by get_storage().
          # get_storage() uses S3_SOURCE_BUCKET_NAME by default.
          # If we want a separate bucket for Vector DB, we need to update store.py or this var.
          # User said "i will create the s3 vectors bucket... manually".
          # So we should probably pass a separate env var S3_VECTOR_BUCKET_NAME and update store.py to use it?
          # Or just use S3_SOURCE_BUCKET_NAME if the user is okay with one bucket.
          # User explicitly said "separate s3 vectors bucket".
          # I need to update store.py to check S3_VECTOR_BUCKET_NAME.
          # But for now I'll pass it.
          S3_VECTOR_BUCKET_NAME          = var.vector_db_bucket_name
          
          # Secrets
          OPENAI_API_KEY                 = var.openai_api_key
          DEEPSEEK_API_KEY               = var.deepseek_api_key
          CLERK_SECRET_KEY               = var.clerk_secret_key
          NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = var.clerk_publishable_key
          GITHUB_TOKEN                   = var.github_token
        }
      }
    }
    authentication_configuration {
      access_role_arn = var.access_role_arn
    }
    auto_deployments_enabled = true
  }

  instance_configuration {
    instance_role_arn = var.instance_role_arn
    cpu               = "2048"
    memory            = "4096"
  }

  health_check_configuration {
    protocol = "HTTP"
    path     = "/health" # Dedicated health endpoint
    interval = 20        # Max allowed by AWS (addressing user request for less aggressive checks)
    timeout  = 20        # Max allowed by AWS
    healthy_threshold = 1 # Quick recovery
  }
}

output "service_url" {
  value = aws_apprunner_service.service.service_url
}
