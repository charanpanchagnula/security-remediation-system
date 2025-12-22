variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "project_name" {
  type = string
}

variable "artifacts_bucket_arn" {
  type = string
}

variable "sqs_queue_arn" {
  type = string
}

variable "results_bucket_arn" {
  type = string
}

variable "vector_db_bucket_name" {
  type = string
}

# ... (Previous code)
# 1. Instance Role (Runtime permissions for the application)
resource "aws_iam_role" "apprunner_instance_role" {
  name = "${var.project_name}-instance-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "tasks.apprunner.amazonaws.com"
        }
      }
    ]
  })
}
# Policy for S3 Artifacts & Results Access
resource "aws_iam_policy" "artifacts_policy" {
  name = "${var.project_name}-artifacts-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          var.artifacts_bucket_arn,
          "${var.artifacts_bucket_arn}/*",
          var.results_bucket_arn,
          "${var.results_bucket_arn}/*"
        ]
      }
    ]
  })
}

# Policy for SQS Access
resource "aws_iam_policy" "sqs_policy" {
  name = "${var.project_name}-sqs-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = var.sqs_queue_arn
      }
    ]
  })
}

# Policy for Vector DB S3 Access (Manual Bucket)
resource "aws_iam_policy" "vector_db_policy" {
  name = "${var.project_name}-vector-policy-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3vectors:PutVectors",
          "s3vectors:GetVectors",
          "s3vectors:QueryVectors",
          "s3vectors:ListVectorBuckets",
          "s3vectors:ListVectorIndexes"
        ]
        Resource = [
          "arn:aws:s3vectors:${var.aws_region}:${var.account_id}:vectorbucket/${var.vector_db_bucket_name}",
          "arn:aws:s3vectors:${var.aws_region}:${var.account_id}:bucket/${var.vector_db_bucket_name}/index/*"
        ]
      }
    ]
  })
}

# Attach policies
resource "aws_iam_role_policy_attachment" "attach_artifacts" {
  role       = aws_iam_role.apprunner_instance_role.name
  policy_arn = aws_iam_policy.artifacts_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_sqs" {
  role       = aws_iam_role.apprunner_instance_role.name
  policy_arn = aws_iam_policy.sqs_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_vector" {
  role       = aws_iam_role.apprunner_instance_role.name
  policy_arn = aws_iam_policy.vector_db_policy.arn
}

# 2. Access Role (Build-time permissions for ECR)
resource "aws_iam_role" "apprunner_access_role" {
  name = "${var.project_name}-access-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "build.apprunner.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_ecr_access" {
  role       = aws_iam_role.apprunner_access_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess"
}

output "instance_role_arn" {
  value = aws_iam_role.apprunner_instance_role.arn
}

output "access_role_arn" {
  value = aws_iam_role.apprunner_access_role.arn
}
