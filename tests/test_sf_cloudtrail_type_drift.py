# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CloudTrail requestParameters whose type drifts between APIs (#485, #430)"""
import json

import pytest

from siem import sf_cloudtrail

S3KEY = ('AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/06/'
         '111122223333_CloudTrail_us-east-1_20261006T1320Z_abc.json.gz')


def _record(event_source, event_name, request_parameters, event_id='1'):
    return {
        'eventVersion': '1.08',
        'userIdentity': {'type': 'IAMUser', 'accountId': '111122223333',
                         'userName': 'alice'},
        'eventTime': '2026-10-06T13:17:29Z',
        'eventSource': event_source,
        'eventName': event_name,
        'awsRegion': 'us-east-1',
        'sourceIPAddress': '192.0.2.1',
        'userAgent': 'aws-cli/2.0',
        'requestParameters': request_parameters,
        'responseElements': None,
        'eventID': event_id,
        'recipientAccountId': '111122223333',
    }


def _load(parse_json_log, *records):
    raw = json.dumps({'Records': list(records)})
    return [r['doc'] for r in parse_json_log(raw, 'cloudtrail', S3KEY)]


def test_filters_list_of_objects_is_stringified(parse_json_log):
    rp = {'filters': [{'key': 'Owner', 'values': ['Self']}]}
    doc, = _load(parse_json_log,
                 _record('ssm.amazonaws.com', 'ListDocuments', rp))
    assert isinstance(doc['requestParameters']['filters'], str)
    assert 'Owner' in doc['requestParameters']['filters']


def test_filters_dict_is_stringified():
    logdata = {'requestParameters': {'filters': {'key': 'Owner'}},
               'event': {}, 'cloud': {}}
    out = sf_cloudtrail.transform(logdata)
    assert out['requestParameters']['filters'] == "{'key': 'Owner'}"


@pytest.mark.parametrize('value', ['tag:Name', ['a', 'b'], [], 3])
def test_filters_scalar_is_untouched(value):
    logdata = {'requestParameters': {'filters': value},
               'event': {}, 'cloud': {}}
    out = sf_cloudtrail.transform(logdata)
    assert out['requestParameters']['filters'] == value


def test_metrics_list_of_objects_is_stringified(parse_json_log):
    rp = {'metrics': [{'name': 'CPU', 'unit': 'Percent'}]}
    doc, = _load(parse_json_log,
                 _record('monitoring.amazonaws.com', 'PutMetricStream', rp))
    assert isinstance(doc['requestParameters']['metrics'], str)


def test_metrics_list_of_strings_is_untouched():
    logdata = {'requestParameters': {'metrics': ['CPU', 'Mem']},
               'event': {}, 'cloud': {}}
    out = sf_cloudtrail.transform(logdata)
    assert out['requestParameters']['metrics'] == ['CPU', 'Mem']


def test_ecs_runtask_hidden_environment_is_wrapped(parse_json_log):
    rp = {'platformVersion': 'LATEST',
          'overrides': {
              'containerOverrides': [
                  {'name': 'default', 'command': ['bin/echo'],
                   'environment': 'HIDDEN_DUE_TO_SECURITY_REASONS'}],
              'cpu': '2048', 'memory': '4096'}}
    doc, = _load(parse_json_log,
                 _record('ecs.amazonaws.com', 'RunTask', rp))
    co = doc['requestParameters']['overrides']['containerOverrides'][0]
    assert co['environment'] == {'value': 'HIDDEN_DUE_TO_SECURITY_REASONS'}
    assert co['name'] == 'default'


def test_batch_submitjob_environment_list_is_untouched(parse_json_log):
    env = [{'name': 'MANAGED_BY_AWS', 'value': 'STARTED_BY_STEP_FUNCTIONS'},
           {'name': 'JOB_DATA', 'value': ''}]
    rp = {'jobName': 'Utility',
          'containerOverrides': {'command': ['bin/echo'],
                                 'environment': env}}
    doc, = _load(parse_json_log,
                 _record('batch.amazonaws.com', 'SubmitJob', rp))
    # es-loader drops empty values, so JOB_DATA loses its '' value
    assert doc['requestParameters']['containerOverrides']['environment'] == [
        env[0], {'name': 'JOB_DATA'}]


def test_batch_hidden_environment_is_wrapped():
    hidden = 'HIDDEN_DUE_TO_SECURITY_REASONS'
    logdata = {'requestParameters': {
        'containerOverrides': {'environment': hidden}},
        'event': {}, 'cloud': {}}
    out = sf_cloudtrail.transform(logdata)
    assert out['requestParameters']['containerOverrides']['environment'] == {
        'value': 'HIDDEN_DUE_TO_SECURITY_REASONS'}


def test_request_parameters_null_is_safe():
    logdata = {'requestParameters': None, 'event': {}, 'cloud': {}}
    assert sf_cloudtrail.transform(logdata)['requestParameters'] is None
