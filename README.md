# cloud-detections

Detect attacks on an AWS account from its cloud logs, not from host logs.

This lab turns on a CloudTrail trail, emulates seven real attacker techniques
with [Stratus Red Team](https://stratus-red-team.cloud/), and detects each one
from the trail. Every technique has a [Sigma](https://sigmahq.io/) rule, a Wazuh
rule converted from it, and an Athena SQL query. The week before this one
(week 10) scanned an account's *configuration*; this week watches what someone
*does* in the account.

## What it does

1. **Deploys the lab** (Terraform): a multi-region CloudTrail trail with log-file
   validation, writing to a private, encrypted S3 bucket; a GuardDuty detector;
   an Athena workgroup with a bytes-scanned cap and a CloudTrail table that uses
   partition projection; and a least-privilege IAM identity for the SIEM that can
   read only the trail bucket.
2. **Emulates attacks** with Stratus Red Team, across five ATT&CK tactics.
3. **Ships the logs** to a Wazuh SIEM (the week-1 lab's manager), which reads the
   trail bucket with its own read-only keys and raises an alert per technique.
4. **Queries the same logs** with Athena, as a second, SIEM-free way to detect.
5. **Proves it**: a verify script passes only if every technique was detected,
   plus two negative tests (a quiet window, and a disabled rule).

## The seven techniques, and what caught them

| # | Technique (Stratus) | ATT&CK | Sigma rule | Wazuh rule | Own detection | GuardDuty |
|---|---|---|---|---|---|---|
| 1 | `cloudtrail-stop` (StopLogging) | T1562.008 | `cloudtrail_logging_stopped.yml` | 100700 | yes | unavailable |
| 2 | `cloudtrail-event-selectors` (PutEventSelectors) | T1562.008 | `cloudtrail_event_selectors_changed.yml` | 100701 | yes | unavailable |
| 3 | `iam-create-admin-user` (AttachUserPolicy) | T1098.003 | `iam_admin_policy_attached.yml` | 100702 | yes | unavailable |
| 4 | `iam-backdoor-user` (CreateAccessKey) | T1098.001 | `iam_access_key_created.yml` | 100703 | yes | unavailable |
| 5 | `s3-backdoor-bucket-policy` (PutBucketPolicy) | T1537 | `s3_bucket_policy_backdoored.yml` | 100704 | yes | unavailable |
| 6 | `secretsmanager-batch-retrieve-secrets` (BatchGetSecretValue) | T1555.006 | `secretsmanager_batch_retrieve.yml` | 100705 | yes | unavailable |
| 7 | `ses-enumerate` (GetAccountSendingEnabled) | T1580 | `ses_enumeration.yml` | 100706 | yes | unavailable |

All seven fired on their own technique, in both Athena and Wazuh, and stayed
quiet over a window of ordinary read-only activity. GuardDuty reads `unavailable`
because the throwaway AWS account cannot subscribe to it (see "What was learned").

## How to run it

Needs an AWS account (a throwaway, not a real one), the AWS CLI, Terraform, and
Stratus Red Team. The whole run deploys, detonates, collects, and tears down; the
account is left exactly as it started.

```bash
make baseline          # record the account's state, to compare at the end
make deploy            # trail, GuardDuty, Athena, SIEM identity
make env               # write the SIEM's read-only keys to a git-ignored .env

scripts/wazuh_up.sh    # bring up the Wazuh manager + indexer, load the rules
scripts/benign.sh      # record a window of ordinary activity (negative test a)
python3 scripts/detonate.py          # run the seven attacks, record UTC times
# CloudTrail delivers to S3 after a few minutes; wait, then:
python3 scripts/collect.py --wazuh-alerts evidence/wazuh/alerts.json
scripts/wazuh_ingest.sh              # run the Wazuh AWS wodle over the trail
python3 scripts/verify.py --require-wazuh   # the gate: every technique detected
scripts/negative_tests.sh            # quiet window + a disabled rule

python3 scripts/cleanup.py           # stratus cleanup, confirm every technique COLD
make destroy                         # remove the lab
make teardown                        # snapshot again; it must equal the baseline
```

`make test` runs the credential-free checks (the Wazuh ruleset is regenerable
from the Sigma rules, and the Sigma, Wazuh, Athena and registry all agree). CI
runs these and `terraform validate` on every push.

## How a detection works

A CloudTrail record names who did what: `eventSource` (which service),
`eventName` (which API call), `userIdentity` (who), and the request parameters.
A detection is a filter on those fields.

- The **Sigma rule** states the filter once, in a portable form (`sigma/`).
- `convert/sigma_to_wazuh.py` turns each Sigma rule into a **Wazuh rule**
  (`wazuh/local_rules.xml`), a child of Wazuh's AWS base rule that matches the
  same fields as `aws.eventName`, `aws.eventSource`, and so on. This reuses the
  week-5 converter's approach for a new rule class.
- The **Athena SQL** (`athena/`) is the same filter as a query over the raw logs
  in S3, for when there is no SIEM.

One intent, three places it runs. `techniques.yaml` is the single source of
truth that keeps them in step.

## What was learned

- **Cloud detection reads a different log.** Weeks 1–8 read host logs (a Linux
  machine's auth log, file changes, network captures). An attacker in a cloud
  account leaves no host log; the record of what they did is CloudTrail. The
  sensor moves from the machine to the account's own audit trail.
- **The same intent, written for the telemetry you have.** The detection logic
  is identical whether it runs in a SIEM or in Athena. A SIEM gives you alerting
  and correlation; Athena gives you a cheap, ad-hoc query with no server to run.
  A real team uses both: the SIEM for standing detections, the query for a hunt.
- **Partition projection makes the query layer free to run.** The CloudTrail
  table computes each partition's S3 path from the query's date and region, so
  there is never a partition to load by hand, and the workgroup's bytes-scanned
  cap keeps a careless query from running up a bill.
- **A detection that cannot fail proves nothing.** The gate is proven twice: a
  window of ordinary activity raises no alert, and switching one rule off makes
  the verify script fail and name the technique it then misses.
- **GuardDuty could not be turned on in this account.** `CreateDetector` is
  refused with `SubscriptionRequiredException` in every region, even with
  AdministratorAccess and no Organization — an account-level limit, not a
  misconfiguration. On a normal account `make deploy` turns GuardDuty on (free
  for the first 30 days) and the comparison column fills in. The lab records the
  limit rather than hiding it.

Longer notes, the mechanism and the mistakes are in the bootcamp study book.
