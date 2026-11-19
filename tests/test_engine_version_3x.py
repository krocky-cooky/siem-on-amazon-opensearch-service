# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Default engine version 3.x, legacy setting names and saved objects
selection (docs/opensearch3_compatibility.md)."""
import configparser
import json
import os
import sys

import pytest

DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')
sys.path.insert(0, DEPLOY_ES_DIR)
import compat  # noqa: E402


@pytest.mark.parametrize('value,expected', [
    ('OpenSearch_3.5', 3),
    ('OpenSearch_2.19', 2),
    ('Elasticsearch_7.10', 7),
    ('', None),
    ('3.5', None),
    (None, None),
])
def test_engine_major_version(value, expected):
    assert compat.engine_major_version(value) == expected


@pytest.mark.parametrize('value,expected', [
    (None, 'OpenSearch_3.5'),
    ('', 'OpenSearch_3.5'),
    ('garbage', 'OpenSearch_3.5'),
    ('OpenSearch_2.19', 'OpenSearch_2.19'),
    ('OpenSearch_3.7', 'OpenSearch_3.7'),
])
def test_get_engine_version(value, expected):
    assert compat.get_engine_version(value) == expected


def test_default_for_new_domains_is_3x():
    assert compat.engine_major_version(compat.DEFAULT_ENGINE_VERSION) == 3


def test_advanced_option_is_removed_only_for_3x():
    options = {'override_main_response_version': 'true', 'other': '1'}
    assert 'override_main_response_version' not in (
        compat.advanced_options_for('OpenSearch_3.5', options))
    assert compat.advanced_options_for('OpenSearch_3.5', options)[
        'other'] == '1'
    assert compat.advanced_options_for('OpenSearch_2.19', options) == options
    # the argument is not changed
    assert 'override_main_response_version' in options


@pytest.mark.parametrize('version,names,expected', [
    ('3.5.0', ['dashboard.ndjson', 'dashboard.3.x.ndjson'],
     'dashboard.3.x.ndjson'),
    ('2.19.0', ['dashboard.ndjson', 'dashboard.3.x.ndjson'],
     'dashboard.ndjson'),
    # no 3.x set in the zip: the 2.x set is used for 3.x as before
    ('3.5.0', ['dashboard.ndjson'], 'dashboard.ndjson'),
    (None, ['dashboard.ndjson', 'dashboard.3.x.ndjson'], 'dashboard.ndjson'),
])
def test_select_saved_objects_file(version, names, expected):
    assert compat.select_saved_objects_file(names, version) == expected


def test_legacy_kibana_never_uses_3x_set():
    names = ['dashboard.ndjson', 'dashboard.3.x.ndjson']
    assert compat.select_saved_objects_file(
        names, '7.10.2', 'elasticsearch') == 'dashboard.ndjson'


def _load(ini_name):
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, ini_name))
    return data


def test_rename_legacy_settings_for_opensearch():
    data = _load('data.ini')
    rollover = dict(data['index-rollover'])
    cluster = dict(data['cluster-settings'])
    assert any('opendistro.index_state_management.rollover_alias' in v
               for v in rollover.values())
    n1 = compat.rename_legacy_settings(rollover)
    n2 = compat.rename_legacy_settings(cluster)
    assert n1 > 0 and n2 == 1
    for text in list(rollover.values()) + list(cluster.values()):
        json.loads(text)
        assert 'opendistro.' not in text
    assert all('plugins.index_state_management.rollover_alias' in v
               for v in rollover.values())
    alert = json.loads(cluster['opendistro-alert'])
    assert 'plugins.alerting.alert_history_max_age' in json.dumps(alert)


def test_rename_is_idempotent_and_ignores_other_settings():
    section = {'a': json.dumps({'x': {'index.refresh_interval': '30s'}})}
    assert compat.rename_legacy_settings(section) == 0
    section = {'a': '{"opendistro.index_state_management.rollover_alias": '
                    '"log-x"}'}
    assert compat.rename_legacy_settings(section) == 1
    assert compat.rename_legacy_settings(section) == 0
