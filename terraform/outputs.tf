output "app_runner_url" {
  value = module.compute.service_url
}

output "ecr_repository_url" {
  value = module.storage.ecr_repository_url
}

output "sqs_queue_url" {
  value = module.queue.sqs_queue_url
}

output "artifacts_bucket_name" {
  value = module.storage.artifacts_bucket_name
}
