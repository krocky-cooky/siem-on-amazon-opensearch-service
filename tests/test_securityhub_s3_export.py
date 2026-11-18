# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Security Hub findings export to S3 in JSON (OCSF) (C-6).

The file layout of the export is not documented, so the three shapes that
es-loader can read are tested: one finding per line, a JSON array, and an
object with "findings".
https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-findings-export.html
"""
import json

import pytest

from conftest import load_fixture

EXPORT_KEY = ('SecurityHub-OCSF/AWSLogs/111122223333/'
              'vulnerabilities-202610081601/part-0001.json')
EVENT_FIXTURE = 'securityhub_ocsf_findings_imported_v2.json'


@pytest.fixture
def findings():
    event = json.loads(load_fixture(EVENT_FIXTURE))
    return event['detail']['findings']


@pytest.mark.parametrize('shape', ['ndjson', 'array', 'wrapped'])
def test_export_shapes(parse_json_log, findings, shape):
    if shape == 'ndjson':
        raw = '\n'.join(json.dumps(f) for f in findings)
    elif shape == 'array':
        raw = json.dumps(findings)
    else:
        raw = json.dumps({'findings': findings})
    results = parse_json_log(raw, 'securityhub-ocsf', EXPORT_KEY)
    assert len(results) == len(findings)
    for result in results:
        assert result['index'].startswith('log-ocsf-securityhub-')
        assert result['doc']['@log_type'].startswith('securityhub-ocsf-')


def test_export_and_event_have_same_id(parse_json_log, findings):
    """the same finding from EventBridge and S3 export is one document"""
    from_event = parse_json_log(
        load_fixture(EVENT_FIXTURE), 'securityhub-ocsf',
        'SecurityHub-OCSF/Findings_Imported_V2/')
    from_export = parse_json_log(
        json.dumps(findings), 'securityhub-ocsf', EXPORT_KEY)
    assert [r['id'] for r in from_event] == [r['id'] for r in from_export]


def test_other_logtypes_keep_strict_delimiter(parse_json_log):
    """CloudTrail ignores a json without Records, as before"""
    raw = json.dumps({'not_records': []})
    assert parse_json_log(raw, 'cloudtrail', 'AWSLogs/CloudTrail/x.json') == []
