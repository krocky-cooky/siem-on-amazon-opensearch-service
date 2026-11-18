# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CloudTrail requestParameters.startTime / endTime accept ISO 8601 (#492)"""
import configparser
import json
import os
from datetime import datetime

import pytest

DEPLOY_ES = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')
FIELDS = ('requestParameters.startTime', 'requestParameters.endTime')


def _properties(ini_name):
    config = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    config.read(os.path.join(DEPLOY_ES, 'data.ini'))
    if ini_name != 'data.ini':
        config.read(os.path.join(DEPLOY_ES, ini_name))
    template = json.loads(
        config['component-templates']['component_template_log-aws-cloudtrail'])
    return template['template']['mappings']['properties']


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
@pytest.mark.parametrize('field', FIELDS)
def test_formats(ini_name, field):
    formats = _properties(ini_name)[field]['format'].split('||')
    # legacy console format, ISO 8601 and epoch millis
    assert 'MMM d, yyyy[,] h:mm:ss a' in formats
    assert 'strict_date_optional_time' in formats
    assert 'epoch_millis' in formats


def test_issue_sample_is_iso8601():
    # value from the rejected events in the issue
    assert datetime.fromisoformat('2026-10-06T13:17:29Z')
