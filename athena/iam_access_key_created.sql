-- Detection: IAM Access Key Created (MITRE ATT&CK T1098.001)
-- An attacker created a long-lived access key on an IAM user (persistence).
SELECT eventtime, eventname, eventsource,
       useridentity.arn AS actor,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       sourceipaddress, awsregion, eventid
FROM "${db}"."cloudtrail_logs"
WHERE "timestamp" >= '${start_date}' AND "timestamp" <= '${end_date}'
  AND eventsource = 'iam.amazonaws.com'
  AND eventname = 'CreateAccessKey'
  AND eventtime >= '${start}' AND eventtime <= '${end}'
ORDER BY eventtime;
