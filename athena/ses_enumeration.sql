-- Detection: SES Enumeration (MITRE ATT&CK T1580)
-- An attacker enumerated SES sending status (discovery).
SELECT eventtime, eventname, eventsource,
       useridentity.arn AS actor, sourceipaddress, awsregion, eventid
FROM "${db}"."cloudtrail_logs"
WHERE "timestamp" >= '${start_date}' AND "timestamp" <= '${end_date}'
  AND eventsource = 'ses.amazonaws.com'
  AND eventname IN ('GetAccount', 'GetSendQuota', 'GetAccountSendingEnabled', 'ListIdentities')
  AND eventtime >= '${start}' AND eventtime <= '${end}'
ORDER BY eventtime;
