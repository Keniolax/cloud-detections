# Athena is the query layer over the CloudTrail logs: its own results bucket,
# a workgroup with a bytes-scanned cap (so a careless query cannot run up a
# bill), a Glue database, and a CloudTrail table that uses partition
# projection so no partition ever has to be loaded by hand.

resource "aws_s3_bucket" "results" {
  bucket        = local.results_bucket
  force_destroy = true
  tags          = { Name = local.results_bucket }
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_athena_workgroup" "main" {
  name          = "${var.name_prefix}-wg"
  force_destroy = true
  tags          = { Name = "${var.name_prefix}-wg" }

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false

    # Cap every query at 1 GB scanned. The whole lab's logs are a few MB, so
    # this never bites a real query but stops a runaway scan.
    bytes_scanned_cutoff_per_query = 1073741824

    result_configuration {
      output_location = "s3://${aws_s3_bucket.results.id}/query-results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

resource "aws_glue_catalog_database" "main" {
  name = replace("${var.name_prefix}_db", "-", "_")
}

# The CloudTrail table, defined with the CloudTrail SerDe (which unwraps the
# {"Records":[...]} envelope) and partition projection on region + date. With
# projection on, Athena computes the S3 path for each partition from the query
# predicate, so there is no MSCK REPAIR or ADD PARTITION ever.
resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.main.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                             = "TRUE"
    "classification"                     = "cloudtrail"
    "projection.enabled"                 = "true"
    "projection.region.type"             = "enum"
    "projection.region.values"           = "us-east-1,us-east-2,us-west-1,us-west-2,eu-west-1,eu-central-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,ap-south-1,ca-central-1,sa-east-1"
    "projection.timestamp.type"          = "date"
    "projection.timestamp.range"         = "2026/01/01,NOW"
    "projection.timestamp.format"        = "yyyy/MM/dd"
    "projection.timestamp.interval"      = "1"
    "projection.timestamp.interval.unit" = "DAYS"
    "storage.location.template"          = "s3://${aws_s3_bucket.trail.id}/AWSLogs/${local.account_id}/CloudTrail/$${region}/$${timestamp}"
  }

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "timestamp"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.trail.id}/AWSLogs/${local.account_id}/CloudTrail"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    dynamic "columns" {
      for_each = local.cloudtrail_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}
