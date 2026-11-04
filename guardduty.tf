# GuardDuty detector in the lab region. GuardDuty reads CloudTrail, VPC flow
# logs and DNS logs itself (not our trail) and raises its own findings; the
# week compares them with the CloudTrail detections. Free for the first 30
# days in a new account, then billed, so teardown deletes it.

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = { Name = "${var.name_prefix}-detector" }
}
