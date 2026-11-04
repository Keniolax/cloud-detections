# GuardDuty detector in the lab region. GuardDuty reads CloudTrail, VPC flow
# logs and DNS logs itself (not our trail) and raises its own findings; the
# week compares them with the CloudTrail detections. Free for the first 30
# days in a new account, then billed, so teardown deletes it.

# Gated by a variable: on a normal account GuardDuty turns on (free for the
# first 30 days). In the bootcamp throwaway account, CreateDetector is refused
# with SubscriptionRequiredException even with AdministratorAccess and no
# Organization, so this run sets enable_guardduty=false and the comparison
# records GuardDuty as unavailable here (see STATE.md and WAITING.md).
resource "aws_guardduty_detector" "main" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = { Name = "${var.name_prefix}-detector" }
}
