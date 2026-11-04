variable "region" {
  description = "Region for the lab. CloudTrail is multi-region regardless."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name, so the lab is easy to find."
  type        = string
  default     = "seceng-cloud-det"
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # Bucket names are globally unique; the account id makes them deterministic
  # (no random suffix), so a hand teardown can predict them.
  trail_bucket   = "${var.name_prefix}-trail-${local.account_id}"
  results_bucket = "${var.name_prefix}-athena-results-${local.account_id}"

  # The CloudTrail record schema, as the CloudTrail SerDe expects it (lowercase
  # column names, nested structs as Hive type strings).
  cloudtrail_columns = [
    { name = "eventversion", type = "string" },
    { name = "useridentity", type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>" },
    { name = "eventtime", type = "string" },
    { name = "eventsource", type = "string" },
    { name = "eventname", type = "string" },
    { name = "awsregion", type = "string" },
    { name = "sourceipaddress", type = "string" },
    { name = "useragent", type = "string" },
    { name = "errorcode", type = "string" },
    { name = "errormessage", type = "string" },
    { name = "requestparameters", type = "string" },
    { name = "responseelements", type = "string" },
    { name = "additionaleventdata", type = "string" },
    { name = "requestid", type = "string" },
    { name = "eventid", type = "string" },
    { name = "readonly", type = "string" },
    { name = "resources", type = "array<struct<arn:string,accountid:string,type:string>>" },
    { name = "eventtype", type = "string" },
    { name = "apiversion", type = "string" },
    { name = "recipientaccountid", type = "string" },
    { name = "serviceeventdetails", type = "string" },
    { name = "sharedeventid", type = "string" },
    { name = "vpcendpointid", type = "string" },
    { name = "tlsdetails", type = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>" },
  ]
}
