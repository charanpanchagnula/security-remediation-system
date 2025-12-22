variable "environment" {
  type = string
}

variable "project_name" {
  type = string
}

resource "aws_ecr_repository" "app_repo" {
  name                 = "${var.project_name}-repo-${var.environment}"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_s3_bucket" "artifacts_bucket" {
  bucket        = "${var.project_name}-source-artifacts-${var.environment}"
  force_destroy = true
}

resource "aws_s3_bucket" "results_bucket" {
  bucket        = "${var.project_name}-scan-results-${var.environment}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "artifacts_versioning" {
  bucket = aws_s3_bucket.artifacts_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app_repo.repository_url
}

output "artifacts_bucket_arn" {
  value = aws_s3_bucket.artifacts_bucket.arn
}

output "artifacts_bucket_name" {
  value = aws_s3_bucket.artifacts_bucket.id
}

output "results_bucket_arn" {
  value = aws_s3_bucket.results_bucket.arn
}

output "results_bucket_name" {
  value = aws_s3_bucket.results_bucket.id
}
