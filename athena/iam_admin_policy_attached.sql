-- Detection: Administrator Policy Attached to IAM User (MITRE ATT&CK T1098.003)
-- An attacker granted AdministratorAccess to a user (persistence / priv-esc).
SELECT eventtime, eventname, eventsource,
       useridentity.arn AS actor,
       json_extract_scalar(requestparameters, '$.userName')  AS target_user,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
       sourceipaddress, awsregion, eventid
FROM "${db}"."cloudtrail_logs"
WHERE "timestamp" >= '${start_date}' AND "timestamp" <= '${end_date}'
  AND eventsource = 'iam.amazonaws.com'
  AND eventname = 'AttachUserPolicy'
  AND json_extract_scalar(requestparameters, '$.policyArn') LIKE '%AdministratorAccess%'
  AND eventtime >= '${start}' AND eventtime <= '${end}'
ORDER BY eventtime;
