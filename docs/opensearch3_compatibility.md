# Compatibility with OpenSearch 3.x

[Back To README](../README.md)

This page lists what was checked for OpenSearch 3.x and what still has to be confirmed. The default engine version of new domains is not changed by this check (see the issue for the default and the saved objects).

How this was checked: the repository (index templates, deployment code, saved objects) was compared with the [breaking changes of OpenSearch 3.0](https://docs.opensearch.org/latest/breaking-changes/), the [plugin settings documentation](https://docs.opensearch.org/latest/observing-your-data/alerting/settings/) and the AWS guidance for [upgrading domains to 3.x](https://repost.aws/fr/articles/ARJmI4RiskRji3rRXhmi-9IA/upgrading-amazon-opensearch-domain-from-v2-x-to-3-x-prerequisites-breaking-changes-and-best-practices). It was **not** run against a real 3.x domain, so every item marked "confirm on a 3.x domain" is open.

## Result

| Area | Item | Status | Detail |
|---|---|---|---|
| Upgrade path | Domain must be on 2.19 before 3.x | Documented | Direct upgrades from older 2.x versions are not supported. The solution default is `OpenSearch_2.19` |
| Upgrade path | Indices created before 2.x | Action by users | Indices created in OpenSearch 1.3 or Elasticsearch 7.10 must be reindexed before the upgrade. SIEM indices created by v2.x of this solution on OpenSearch 2.x are not affected |
| Index templates | Removed index settings | OK | The templates do not use `index.store.hybrid.mmap.extensions` or the removed `index.knn.*` settings (checked by `tests/test_opensearch3_compat.py`) |
| Index templates | `opendistro.index_state_management.rollover_alias` | Confirm on a 3.x domain | The ISM documentation uses `plugins.index_state_management.*`. The `opendistro.` prefix is a legacy name. If it is not accepted on 3.x, template updates fail for rollover indices. `plugins.index_state_management.rollover_alias` is the candidate replacement |
| Deployment code | Alerting cluster settings `opendistro.alerting.alert_history_*` | Confirm on a 3.x domain | The Alerting documentation lists `plugins.alerting.alert_history_*`. The `opendistro.` names are legacy. The deployment only logs the response of this request, so a rejection does not stop the deployment, but the history retention would not be applied |
| Deployment code | Advanced option `override_main_response_version` | Confirm on a 3.x domain | OpenSearch removed the `compatibility.override_main_response_version` setting in 3.0. Check that the Amazon OpenSearch Service API still accepts this advanced option when you create a 3.x domain. It is only used when the solution creates a new domain |
| Deployment code | `_opendistro` URLs | OK | They are used only for Elasticsearch 7.10 domains. OpenSearch domains use `_plugins` |
| Loader | Document ID longer than 512 bytes | Fixed | 3.x enforces the limit in the bulk API too. es-loader now replaces an ID longer than 512 bytes with its MD5 hash. IDs that are not longer are not changed |
| Saved objects | `config` objects | OK | The import already removes version-pinned `config` objects, which 3.x rejects, and applies them through the Advanced Settings API. `config/opensearch_3.5.0.ndjson` exists |
| Saved objects | Removed features | OK | No Gantt chart visualization and no `discover:newExperience` setting are in the saved objects |
| Saved objects | Timeline (2) and region map (16) visualizations | Confirm on a 3.x domain | They are not listed in the breaking changes, but they must be opened once on a 3.x Dashboards |
| Field types | `flat_object` and other mappings | Confirm on a 3.x domain | No change is known. The Lucene 10 upgrade does not change mapping types, but the template update on 3.x was not run |
| Date formats | `MMM d, yyyy[,] h:mm:ss a` of Inspector | Confirm on a 3.x domain | 3.x runs on JDK 21. Check that a date such as `Nov 2, 2026, 2:56:00 PM` is still parsed |

## Required changes found

1. Document IDs: done in es-loader (this change)
2. Replace `opendistro.*` settings by `plugins.*` settings, if a 3.x domain rejects them: `opendistro.index_state_management.rollover_alias` in the rollover index templates and `opendistro.alerting.*` in the cluster settings. Elasticsearch 7.10 domains need the old names, so the replacement must depend on the distribution
3. Confirm the advanced option `override_main_response_version` when creating a 3.x domain

Items 2 and 3 are not changed here, because the new names could not be confirmed against a running 3.x domain, and a wrong change would break 2.x deployments.

## How to confirm the open items

1. Restore a snapshot of a test domain, or create a new domain with `OpenSearch_2.19`, and deploy this solution
2. Upgrade the domain to 3.x (a blue/green deployment)
3. Update the stack so that the configuration function runs again, then check the CloudWatch Logs of `aes-siem-configure-aes` for non-200 responses of the cluster settings and index templates
4. Open the dashboards and check the timeline and region map visualizations
5. Load an Inspector finding with an `updatedAt` such as `Nov 2, 2026, 2:56:00 PM`
