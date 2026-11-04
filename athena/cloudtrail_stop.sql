-- Detection: CloudTrail Logging Stopped (MITRE ATT&CK T1562.008)
-- An attacker stopped a trail to blind the audit log (defence evasion).
SELECT eventtime, eventname, eventsource,
       useridentity.arn AS actor, sourceipaddress, awsregion, eventid
FROM "${db}"."cloudtrail_logs"
WHERE "timestamp" >= '${start_date}' AND "timestamp" <= '${end_date}'
  AND eventsource = 'cloudtrail.amazonaws.com'
  AND eventname = 'StopLogging'
  AND eventtime >= '${start}' AND eventtime <= '${end}'
ORDER BY eventtime;
