variable "environment" {
  type = string
}

variable "project_name" {
  type = string
}

resource "aws_sqs_queue" "task_queue" {
  name                      = "${var.project_name}-tasks-${var.environment}"
  visibility_timeout_seconds = 600 # 10 mins (Scan takes time)
  message_retention_seconds  = 86400 # 1 day
}

resource "aws_sqs_queue" "dlq" {
  name = "${var.project_name}-tasks-dlq-${var.environment}"
}

output "sqs_queue_url" {
  value = aws_sqs_queue.task_queue.id
}

output "sqs_queue_arn" {
  value = aws_sqs_queue.task_queue.arn
}
