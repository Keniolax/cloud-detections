-- Detection: Bulk Retrieval of Secrets Manager Secrets (MITRE ATT&CK T1555.006)
-- An attacker pulled many secrets at once (credential access).
SELECT eventtime, eventname, eventsource,
       useridentity.arn AS actor, sourceipaddress, awsregion, eventid
FROM "${db}"."cloudtrail_logs"
WHERE "timestamp" >= '${start_date}' AND "timestamp" <= '${end_date}'
  AND eventsource = 'secretsmanager.amazonaws.com'
  AND eventname = 'BatchGetSecretValue'
  AND eventtime >= '${start}' AND eventtime <= '${end}'
ORDER BY eventtime;
