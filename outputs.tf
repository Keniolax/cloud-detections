output "trail_bucket" {
  description = "S3 bucket holding the CloudTrail logs."
  value       = aws_s3_bucket.trail.id
}

output "trail_name" {
  description = "CloudTrail trail name."
  value       = aws_cloudtrail.main.name
}

output "athena_workgroup" {
  value = aws_athena_workgroup.main.name
}

output "athena_database" {
  value = aws_glue_catalog_database.main.name
}

output "athena_table" {
  value = aws_glue_catalog_table.cloudtrail.name
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "siem_user" {
  value = aws_iam_user.siem.name
}

# Written to the git-ignored .env by `make env`, never printed to the log.
output "siem_access_key_id" {
  value     = aws_iam_access_key.siem.id
  sensitive = true
}

output "siem_secret_access_key" {
  value     = aws_iam_access_key.siem.secret
  sensitive = true
}
