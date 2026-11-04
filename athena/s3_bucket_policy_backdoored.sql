-- Detection: S3 Bucket Policy Changed to Allow External Access (MITRE ATT&CK T1537)
-- An attacker rewrote a bucket policy to allow another account to read it.
SELECT eventtime, eventname, eventsource,
       useridentity.arn AS actor,
       json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
       sourceipaddress, awsregion, eventid
FROM "${db}"."cloudtrail_logs"
WHERE "timestamp" >= '${start_date}' AND "timestamp" <= '${end_date}'
  AND eventsource = 's3.amazonaws.com'
  AND eventname = 'PutBucketPolicy'
  AND eventtime >= '${start}' AND eventtime <= '${end}'
ORDER BY eventtime;
