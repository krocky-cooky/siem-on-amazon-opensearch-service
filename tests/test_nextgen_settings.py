# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Retention / warm tier settings for OpenSearch Serverless NextGen.

index.data.retention and index.warm.after are documented at
https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-lifecycle.html
"""
import configparser
import json
import os
import sys

import pytest

DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')
sys.path.insert(0, DEPLOY_ES_DIR)
import nextgen  # noqa: E402


@pytest.mark.parametrize('endpoint,expected', [
    ('abc123.aoss.us-east-1.on.aws', True),
    ('abc123.us-east-1.aoss.amazonaws.com', False),
    ('d.ap-northeast-1.es.amazonaws.com', False),
    ('', False),
    (None, False),
])
def test_is_nextgen_endpoint(endpoint, expected):
    assert nextgen.is_nextgen_endpoint(endpoint) is expected


@pytest.mark.parametrize('retention,warm,expected', [
    ('', '', {}),
    ('90', '', {'index.data.retention': '90d'}),
    ('90', '7', {'index.data.retention': '90d', 'index.warm.after': '7d'}),
    ('', '7', {'index.warm.after': '7d'}),
    ('3650', '1', {'index.data.retention': '3650d',
                   'index.warm.after': '1d'}),
    # invalid values are ignored
    ('0', '', {}),
    ('3651', '', {}),
    ('abc', '', {}),
    ('90', '0', {'index.data.retention': '90d'}),
    ('30', '31', {'index.data.retention': '30d'}),
])
def test_build_index_settings(retention, warm, expected):
    assert nextgen.build_index_settings(retention, warm) == expected


def test_apply_index_settings_keeps_existing_values():
    templates = {
        'a': json.dumps({'index_patterns': ['log-a-*'], 'template': {}}),
        'b': json.dumps({'index_patterns': ['log-b-*'], 'template': {
            'settings': {'index.data.retention': '10d'}}}),
        'c': json.dumps({'index_patterns': ['log-c-*']}),
    }
    changed = nextgen.apply_index_settings(
        templates, {'index.data.retention': '90d'})
    assert changed == 2
    assert json.loads(templates['a'])['template']['settings'] == {
        'index.data.retention': '90d'}
    assert json.loads(templates['b'])['template']['settings'] == {
        'index.data.retention': '10d'}
    assert json.loads(templates['c'])['template']['settings'] == {
        'index.data.retention': '90d'}


def test_apply_index_settings_without_settings_is_noop():
    templates = {'a': json.dumps({'template': {}})}
    assert nextgen.apply_index_settings(templates, {}) == 0
    assert json.loads(templates['a']) == {'template': {}}


def test_apply_to_real_serverless_templates():
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, 'data.ini'))
    data.read(os.path.join(DEPLOY_ES_DIR, 'data-serverless.ini'))
    templates = dict(data['index-templates'])
    settings = nextgen.build_index_settings('90', '7')
    changed = nextgen.apply_index_settings(templates, settings)
    assert changed == len(templates)
    for text in templates.values():
        applied = json.loads(text)['template']['settings']
        assert applied['index.data.retention'] == '90d'
        assert applied['index.warm.after'] == '7d'
