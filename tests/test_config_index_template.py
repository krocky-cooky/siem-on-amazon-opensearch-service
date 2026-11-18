# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Config index must allow large Config snapshots (#474)."""
import configparser
import json
import os

import pytest

DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')
MIN_TOTAL_FIELDS = 8000


def _config_template(ini_name):
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, ini_name))
    return json.loads(
        data['component-templates']['component_template_log-aws-config'])


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
def test_config_total_fields_limit(ini_name):
    template = _config_template(ini_name)
    limit = template['template']['settings'][
        'index.mapping.total_fields.limit']
    assert int(limit) >= MIN_TOTAL_FIELDS


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
def test_config_template_version_bumped(ini_name):
    # the version tells operators which template revision is installed
    assert _config_template(ini_name)['version'] >= 3


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
def test_config_mapping_unchanged(ini_name):
    # B-4a must not change configuration.* structure (B-4 is v3.0.0)
    props = _config_template(ini_name)['template']['mappings']['properties']
    content = props['configuration.AWS:AWSComponent.Content']
    assert content['type'] == 'nested'
