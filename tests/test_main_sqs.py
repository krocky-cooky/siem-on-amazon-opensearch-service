# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for es_loader index.main() event routing (#476).

main() is extracted with ast, like create_logconfig in conftest.py,
because importing index.py connects to OpenSearch.
"""
import ast
import json
import os

import pytest

ES_LOADER_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'es_loader')


def _s3_record(key):
    return {'eventSource': 'aws:s3',
            's3': {'bucket': {'name': 'test-bucket'},
                   'object': {'key': key, 'size': 1}}}


def _sqs_message(message_id, body):
    return {'messageId': message_id, 'eventSource': 'aws:sqs',
            'messageAttributes': {}, 'body': json.dumps(body)}


@pytest.fixture
def main_func():
    with open(os.path.join(ES_LOADER_DIR, 'index.py')) as f:
        tree = ast.parse(f.read())
    funcs = [n for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name == 'main']
    calls = []
    failing_keys = set()

    def process_record(record):
        key = record['s3']['object']['key']
        calls.append(key)
        if key in failing_keys:
            raise RuntimeError(f'failed {key}')

    namespace = {'json': json, 'process_record': process_record}
    exec(compile(ast.Module(body=funcs, type_ignores=[]), 'index.py',
                 'exec'), namespace)
    return namespace['main'], calls, failing_keys


def test_sqs_control_tower_failure_reports_message_id(main_func):
    """Failure inside the nested Records loop must report the SQS messageId
    instead of raising KeyError: 'messageId' (#476)."""
    main, calls, failing_keys = main_func
    failing_keys.add('ct/bad.json.gz')
    event = {'Records': [
        _sqs_message('msg-ok', {'Records': [_s3_record('ct/ok.json.gz')]}),
        _sqs_message('msg-ng', {'Records': [_s3_record('ct/a.json.gz'),
                                            _s3_record('ct/bad.json.gz')]}),
    ]}
    assert main(event, None) == [{'itemIdentifier': 'msg-ng'}]
    assert calls == ['ct/ok.json.gz', 'ct/a.json.gz', 'ct/bad.json.gz']


def test_sqs_control_tower_success(main_func):
    main, calls, _ = main_func
    event = {'Records': [_sqs_message(
        'msg-1', {'Records': [_s3_record('ct/1.gz'), _s3_record('ct/2.gz')]})]}
    assert main(event, None) == []
    assert calls == ['ct/1.gz', 'ct/2.gz']


def test_sqs_splitted_log_failure(main_func):
    main, calls, failing_keys = main_func
    failing_keys.add('split/bad.gz')
    event = {'Records': [
        _sqs_message('msg-1', _s3_record('split/ok.gz')),
        _sqs_message('msg-2', _s3_record('split/bad.gz')),
    ]}
    assert main(event, None) == [{'itemIdentifier': 'msg-2'}]
    assert calls == ['split/ok.gz', 'split/bad.gz']


def test_sqs_invalid_body_reports_message_id(main_func):
    main, calls, _ = main_func
    event = {'Records': [{'messageId': 'msg-bad', 'eventSource': 'aws:sqs',
                          'messageAttributes': {}, 'body': 'not json'}]}
    assert main(event, None) == [{'itemIdentifier': 'msg-bad'}]
    assert calls == []


def test_sns_nested_records(main_func):
    main, calls, _ = main_func
    message = {'Records': [_s3_record('sns/1.gz'), _s3_record('sns/2.gz')]}
    event = {'Records': [{'EventSource': 'aws:sns',
                          'Sns': {'Message': json.dumps(message)}}]}
    assert main(event, None) == []
    assert calls == ['sns/1.gz', 'sns/2.gz']
