# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Engine version helpers and legacy setting names for OpenSearch 3.x.

See docs/opensearch3_compatibility.md
"""
import json
import re

DEFAULT_ENGINE_VERSION = 'OpenSearch_3.5'
RE_ENGINE_VERSION = re.compile(
    r'^(OpenSearch|Elasticsearch)_([0-9]+)\.([0-9]+)$')

# legacy name -> name of OpenSearch (1.0 and later)
LEGACY_SETTING_NAMES = {
    'opendistro.index_state_management.rollover_alias':
        'plugins.index_state_management.rollover_alias',
    'opendistro.alerting.alert_history_max_age':
        'plugins.alerting.alert_history_max_age',
    'opendistro.alerting.alert_history_retention_period':
        'plugins.alerting.alert_history_retention_period',
}


def engine_major_version(engine_version):
    """'OpenSearch_3.5' -> 3, invalid -> None"""
    m = RE_ENGINE_VERSION.match(str(engine_version))
    if not m:
        return None
    return int(m.group(2))


def get_engine_version(value):
    """Return a valid engine version for a new domain. An empty or invalid
    value gets the default."""
    if value and engine_major_version(value) is not None:
        return value
    return DEFAULT_ENGINE_VERSION


def advanced_options_for(engine_version, advanced_options):
    """OpenSearch removed compatibility.override_main_response_version in
    3.0, so the advanced option is not set for 3.x domains."""
    major = engine_major_version(engine_version)
    options = dict(advanced_options)
    if major is not None and major >= 3:
        options.pop('override_main_response_version', None)
    return options


SAVED_OBJECTS_2X = 'dashboard.ndjson'
SAVED_OBJECTS_3X = 'dashboard.3.x.ndjson'


def select_saved_objects_file(names, dashboards_version,
                              dist_name='opensearch'):
    """Select the saved objects file of the zip for the running Dashboards.

    dashboard.3.x.ndjson is used for Dashboards 3.x if it is in the zip.
    Otherwise dashboard.ndjson (exported from 2.x) is used.
    """
    if dist_name != 'opensearch':
        # Kibana of Elasticsearch 7.10 has version 7.x
        return SAVED_OBJECTS_2X
    m = re.match(r'\s*(\d+)', str(dashboards_version or ''))
    major = int(m.group(1)) if m else None
    if major is not None and major >= 3 and SAVED_OBJECTS_3X in names:
        return SAVED_OBJECTS_3X
    return SAVED_OBJECTS_2X


def rename_legacy_settings(section):
    """Rename legacy opendistro setting names to the names of OpenSearch in
    a section of data.ini (dict of name -> JSON text). Return the number of
    changed items. Do not use it for Elasticsearch domains.
    """
    changed = 0
    for name, text in list(section.items()):
        new_text = text
        for old, new in LEGACY_SETTING_NAMES.items():
            new_text = new_text.replace(f'"{old}"', f'"{new}"')
        if new_text != text:
            json.loads(new_text)
            section[name] = new_text
            changed += 1
    return changed
