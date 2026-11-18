# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Inspector date fields must accept every updatedAt format (#484)."""
import configparser
import json
import os

import pytest

DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')
DATE_FIELDS = ('inspector.firstObservedAt', 'inspector.lastObservedAt',
               'inspector.updatedAt')
# legacy, Inspector2 EventBridge format since 2026, ISO 8601
REQUIRED_FORMATS = ('MMM d, yyyy[,] h:mm:ss a',
                    'EEE MMM d HH:mm:ss[.SSS] z yyyy',
                    'strict_date_optional_time')


def _inspector_properties(ini_name):
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, ini_name))
    template = json.loads(
        data['component-templates']['component_template_log-aws-inspector'])
    return template['template']['mappings']['properties']


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
@pytest.mark.parametrize('field', DATE_FIELDS)
def test_inspector_date_field_formats(ini_name, field):
    mapping = _inspector_properties(ini_name)[field]
    assert mapping['type'] == 'date'
    formats = mapping['format'].split('||')
    for fmt in REQUIRED_FORMATS:
        assert fmt in formats, f'{ini_name} {field} lacks {fmt}'
