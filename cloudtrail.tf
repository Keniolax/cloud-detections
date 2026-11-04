# The trail: all regions, management events, log-file validation on. This is
# the single telemetry source the whole week detects from.

resource "aws_cloudtrail" "main" {
  name           = "${var.name_prefix}-trail"
  s3_bucket_name = aws_s3_bucket.trail.id

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  # Log all management events, read and write. The attacks this week emulate
  # (StopLogging, CreateUser, PutBucketPolicy, ...) are all management events.
  advanced_event_selector {
    name = "management-events-all"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  tags = { Name = "${var.name_prefix}-trail" }

  depends_on = [aws_s3_bucket_policy.trail]
}
