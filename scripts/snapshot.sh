#!/usr/bin/env bash
# Record the account's security-relevant state, so the teardown can be compared
# with the baseline. No secrets are printed: only resource names, ids and
# settings. Run as:  scripts/snapshot.sh evidence/baseline.txt
set -uo pipefail
out="${1:?usage: snapshot.sh <output-file>}"
region="${AWS_REGION:-us-east-1}"

# Each listing tolerates a service that is not subscribed in this account
# (e.g. GuardDuty before it is turned on), recording the state rather than
# aborting. "(none)" or an error line is itself part of the baseline.
line() { "$@" 2>&1 | tr '\t' '\n' | sort | sed '/^$/d' || true; }

{
  echo "# Account state snapshot"
  echo "# taken: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# account: $(aws sts get-caller-identity --query Account --output text)"
  echo "# region: $region"
  echo

  acct="$(aws sts get-caller-identity --query Account --output text)"

  echo "## S3 buckets"
  line aws s3api list-buckets --query 'Buckets[].Name' --output text

  echo
  echo "## CloudTrail trails"
  line aws cloudtrail list-trails --query 'Trails[].Name' --output text

  echo
  echo "## GuardDuty detectors ($region)"
  line aws guardduty list-detectors --region "$region" --query 'DetectorIds' --output text

  echo
  echo "## Athena workgroups"
  line aws athena list-work-groups --region "$region" --query 'WorkGroups[].Name' --output text

  echo
  echo "## Glue databases"
  line aws glue get-databases --region "$region" --query 'DatabaseList[].Name' --output text

  echo
  echo "## IAM users"
  line aws iam list-users --query 'Users[].UserName' --output text

  echo
  echo "## IAM roles (customer-managed, excluding AWS service-linked)"
  line aws iam list-roles --query 'Roles[?!starts_with(Path, `/aws-service-role/`)].RoleName' --output text

  echo
  echo "## EC2 instances ($region)"
  line aws ec2 describe-instances --region "$region" \
    --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text

  echo
  echo "## EC2 security groups ($region)"
  line aws ec2 describe-security-groups --region "$region" \
    --query 'SecurityGroups[].[GroupId,GroupName]' --output text

  echo
  echo "## Account S3 public access block"
  aws s3control get-public-access-block --account-id "$acct" \
    --query 'PublicAccessBlockConfiguration' --output json 2>&1 || echo "(none set)"
} > "$out"

echo "snapshot written to $out"
