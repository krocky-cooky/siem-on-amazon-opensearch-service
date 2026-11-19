# Detection content (optional)

[Back To README](../README.md)

The solution can create [Security Analytics](https://docs.opensearch.org/latest/security-analytics/) detectors for CloudTrail logs. It is **off by default**. It works on Amazon OpenSearch Service **domains** (OpenSearch 2.5 or later) only: OpenSearch Serverless has no Security Analytics.

This feature was written from the OpenSearch documentation and tested with a fake API in unit tests. It was not run against a real domain, so check the result as described at the end of this page.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `EnableSecurityAnalyticsDetectors` | `false` | Create the detector `aes-siem-cloudtrail` with all pre-packaged CloudTrail rules of Security Analytics |
| `DetectionPacks` | empty | Industry packs, comma-separated: `finance`, `healthcare`. Each pack creates its rules as custom rules and the detector `aes-siem-pack-<pack>` |

Both detectors read `log-aws-cloudtrail-*` and have one trigger for rules of the level `high` and `critical`. The trigger has no notification action, so findings and alerts are shown in the Alerts and Findings pages of OpenSearch Dashboards. Add a notification channel to the trigger as you need.

## When the detectors are created

The configuration function creates the detectors only if an index of `log-aws-cloudtrail-*` exists, because Security Analytics reads the fields of an existing index. On a new deployment, no CloudTrail log is loaded yet, so the function writes a log message and skips this step. After the first CloudTrail logs are loaded, update the stack once more (for example, with the same parameters) so that the function runs again. It never changes a detector or a rule that exists.

## Industry packs

The rules are Sigma rules in `source/lambda/deploy_es/detections/<pack>/`. They use the field names of CloudTrail logs, which the SIEM keeps as they are in the log (`eventName`, `userIdentity.type`, `requestParameters.*` and others).

| Pack | Rules |
|---|---|
| `finance` (privileged IDs and audit trail) | Root console sign-in, console sign-in without MFA, `AdministratorAccess` attached, CloudTrail stopped or deleted, KMS key disabled or scheduled for deletion |
| `healthcare` (patient records) | S3 Block Public Access removed, S3 bucket encryption deleted, RDS snapshot shared publicly, HealthLake export or deletion, Macie disabled |

The packs contain rules only. They do not include dashboards. The rules are examples: review them, and adapt the false positive conditions to your environment (for example, approved break-glass use of the root user). To add your own pack, put Sigma files in a new directory and add its name to `PACKS` in `detections.py`.

## Checks to run after you enable it

1. In OpenSearch Dashboards, open Security Analytics > Detectors, and check that `aes-siem-cloudtrail` or `aes-siem-pack-*` exist and are active
2. Open the detector and check the field mappings. If fields are unmapped, map them for the log type CloudTrail
3. Open the log of the function `aes-siem-configure-aes` in CloudWatch Logs, and check for `mappings` or detector warnings. Security Analytics maps fields per index. If the monthly index changes, a new index may need the mapping again
4. Run a test event, for example a console sign-in without MFA in a test account, and check Findings
