# A dedicated identity for the SIEM, allowed to read the trail bucket and
# nothing else. The Wazuh container gets these keys (through a git-ignored
# .env), never the admin keys. Destroyed at teardown.

resource "aws_iam_user" "siem" {
  name = "${var.name_prefix}-siem"
  tags = { Name = "${var.name_prefix}-siem" }
}

data "aws_iam_policy_document" "siem_read" {
  statement {
    sid       = "ListTrailBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.trail.arn]
  }
  statement {
    sid       = "ReadTrailObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.trail.arn}/*"]
  }
}

resource "aws_iam_user_policy" "siem_read" {
  name   = "read-trail-bucket"
  user   = aws_iam_user.siem.name
  policy = data.aws_iam_policy_document.siem_read.json
}

resource "aws_iam_access_key" "siem" {
  user = aws_iam_user.siem.name
}
