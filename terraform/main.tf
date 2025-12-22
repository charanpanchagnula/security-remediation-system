provider "aws" {
  region = var.aws_region
}

module "networking" {
  source       = "./modules/networking"
  environment  = var.environment
  project_name = var.project_name
}

module "storage" {
  source       = "./modules/storage"
  environment  = var.environment
  project_name = var.project_name
}

module "queue" {
  source       = "./modules/queue"
  environment  = var.environment
  project_name = var.project_name
}

module "iam" {
  source                = "./modules/iam"
  environment           = var.environment
  project_name          = var.project_name
  artifacts_bucket_arn  = module.storage.artifacts_bucket_arn
  results_bucket_arn    = module.storage.results_bucket_arn
  sqs_queue_arn         = module.queue.sqs_queue_arn
  vector_db_bucket_name = var.vector_db_bucket_name
  aws_region            = var.aws_region
  account_id            = var.aws_account_id
}

module "compute" {
  source                = "./modules/compute"
  environment           = var.environment
  project_name          = var.project_name
  ecr_image_uri         = "${module.storage.ecr_repository_url}:v-20251222-075427"
  instance_role_arn     = module.iam.instance_role_arn
  access_role_arn       = module.iam.access_role_arn
  sqs_queue_url         = module.queue.sqs_queue_url
  artifacts_bucket_name = module.storage.artifacts_bucket_name
  results_bucket_name   = module.storage.results_bucket_name
  vector_db_bucket_name = var.vector_db_bucket_name
  
  # Secrets
  openai_api_key        = var.openai_api_key
  deepseek_api_key      = var.deepseek_api_key
  clerk_secret_key      = var.clerk_secret_key
  clerk_publishable_key = var.clerk_publishable_key
  github_token          = var.github_token
}
