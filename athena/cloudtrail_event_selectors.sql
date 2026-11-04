-- Detection: CloudTrail Event Selectors Changed (MITRE ATT&CK T1562.008)
-- An attacker narrowed a trail's event selectors to hide their activity.
SELECT eventtime, eventname, eventsource,
       useridentity.arn AS actor, sourceipaddress, awsregion, eventid
FROM "${db}"."cloudtrail_logs"
WHERE "timestamp" >= '${start_date}' AND "timestamp" <= '${end_date}'
  AND eventsource = 'cloudtrail.amazonaws.com'
  AND eventname = 'PutEventSelectors'
  AND eventtime >= '${start}' AND eventtime <= '${end}'
ORDER BY eventtime;
