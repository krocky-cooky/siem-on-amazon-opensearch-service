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
| Index templates | `opendistro.index_state_management.rollover_alias` | Fixed | The ISM documentation uses `plugins.index_state_management.rollover_alias`. The deployment now uses it for OpenSearch domains. Elasticsearch 7.10 domains keep the old name. Confirm rollover on a 3.x domain |
| Deployment code | Alerting cluster settings `opendistro.alerting.alert_history_*` | Fixed | The Alerting documentation lists `plugins.alerting.alert_history_*`. The deployment now uses them for OpenSearch domains |
| Deployment code | Advanced option `override_main_response_version` | Fixed | OpenSearch removed the `compatibility.override_main_response_version` setting in 3.0, so the option is not set when the solution creates a 3.x domain. It is still set for 2.x |
| Deployment code | `_opendistro` URLs | OK | They are used only for Elasticsearch 7.10 domains. OpenSearch domains use `_plugins` |
| Loader | Document ID longer than 512 bytes | Fixed | 3.x enforces the limit in the bulk API too. es-loader now replaces an ID longer than 512 bytes with its MD5 hash. IDs that are not longer are not changed |
| Saved objects | `config` objects | OK | The import already removes version-pinned `config` objects, which 3.x rejects, and applies them through the Advanced Settings API. `config/opensearch_3.5.0.ndjson` exists |
| Saved objects | Removed features | OK | No Gantt chart visualization and no `discover:newExperience` setting are in the saved objects |
| Saved objects | Timeline (2) and region map (16) visualizations | Confirm on a 3.x domain | They are not listed in the breaking changes, but they must be opened once on a 3.x Dashboards |
| Field types | `flat_object` and other mappings | Confirm on a 3.x domain | No change is known. The Lucene 10 upgrade does not change mapping types, but the template update on 3.x was not run |
| Date formats | `MMM d, yyyy[,] h:mm:ss a` of Inspector | Confirm on a 3.x domain | 3.x runs on JDK 21. Check that a date such as `Nov 2, 2026, 2:56:00 PM` is still parsed |

## Changes made

1. Document IDs longer than 512 bytes are replaced by their MD5 hash (es-loader)
2. The deployment uses `plugins.index_state_management.rollover_alias` and `plugins.alerting.*` for OpenSearch domains
3. The advanced option `override_main_response_version` is not set for 3.x domains
4. The parameter `EngineVersion` sets the engine version of a new domain. The default is `OpenSearch_3.5`. An existing domain is never upgraded by this parameter, so a stack update does not change the domain
5. The saved objects import selects `dashboard.3.x.ndjson` for Dashboards 3.x if the zip has it, and `dashboard.ndjson` (exported from 2.x) otherwise. No 3.x export is shipped yet: it has to be exported from a 3.x Dashboards that has the SIEM saved objects. Until then 3.x imports the 2.x set, as before

Not confirmed against a running 3.x domain: the default `OpenSearch_3.5` string, the rollover with the new setting name, and the import of the 2.x set into Dashboards 3.x. Use `EngineVersion` = `OpenSearch_2.19` to keep the previous behavior for a new domain.

## How to confirm the open items

1. Restore a snapshot of a test domain, or create a new domain with `OpenSearch_2.19`, and deploy this solution
2. Upgrade the domain to 3.x (a blue/green deployment)
3. Update the stack so that the configuration function runs again, then check the CloudWatch Logs of `aes-siem-configure-aes` for non-200 responses of the cluster settings and index templates
4. Open the dashboards and check the timeline and region map visualizations
5. Load an Inspector finding with an `updatedAt` such as `Nov 2, 2026, 2:56:00 PM`
