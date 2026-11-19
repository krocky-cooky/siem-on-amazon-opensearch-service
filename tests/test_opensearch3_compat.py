# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Static checks for OpenSearch 3.x (docs/opensearch3_compatibility.md).

Removed in 3.0 according to
https://docs.opensearch.org/latest/breaking-changes/
"""
import json
import os

import pytest

from siem import utils

ROOT = os.path.join(os.path.dirname(__file__), '..', 'source')
DEPLOY_ES_DIR = os.path.join(ROOT, 'lambda', 'deploy_es')
REMOVED_SETTINGS = (
    'index.store.hybrid.mmap.extensions',
    'index.knn.algo_param.ef_construction',
    'index.knn.algo_param.m',
    'index.knn.space_type',
    'knn.plugin.enabled',
)


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
def test_templates_do_not_use_removed_settings(ini_name):
    with open(os.path.join(DEPLOY_ES_DIR, ini_name)) as f:
        text = f.read()
    for setting in REMOVED_SETTINGS:
        assert setting not in text, f'{setting} is removed in 3.0'


def test_saved_objects_do_not_use_removed_features():
    with open(os.path.join(ROOT, 'saved_objects', 'dashboard.ndjson')) as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get('type') == 'visualization':
                vis_state = json.loads(obj['attributes']['visState'])
                # dashboards-visualizations (Gantt chart) is removed in 3.0
                assert vis_state.get('type') != 'gantt_chart'
            if obj.get('type') == 'config':
                assert 'discover:newExperience' not in obj['attributes']


def test_3x_config_saved_object_exists():
    assert os.path.exists(os.path.join(
        ROOT, 'saved_objects', 'config', 'opensearch_3.5.0.ndjson'))


@pytest.mark.parametrize('doc_id,expected_same', [
    ('11111111-2222-3333-4444-555555555555', True),
    ('a' * 512, True),
    ('a' * 513, False),
    # 3 bytes per character
    ('\u3042' * 171, False),
    ('\u3042' * 170, True),
])
def test_limit_doc_id(doc_id, expected_same):
    result = utils.limit_doc_id(doc_id)
    assert len(result.encode('utf-8')) <= 512
    assert (result == doc_id) is expected_same


def test_limit_doc_id_is_stable():
    long_id = 'x' * 1000
    assert utils.limit_doc_id(long_id) == utils.limit_doc_id(long_id)
    assert len(utils.limit_doc_id(long_id)) == 32
