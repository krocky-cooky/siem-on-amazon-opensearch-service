# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Field masking, sampling and S3-only log types."""
import json

import pytest

from conftest import load_fixture
from siem import masking

CT_KEY = ('AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/01/'
          '111122223333_CloudTrail_us-east-1_20261001T0100Z_abc.json.gz')


# pure functions
def test_parse_mask_spec():
    assert masking.parse_mask_spec('user.name') == ('user.name', 'hash')
    assert masking.parse_mask_spec('source.ip:ip_truncate') == (
        'source.ip', 'ip_truncate')
    # an unknown method is not a method
    assert masking.parse_mask_spec('a:b') == ('a:b', 'hash')
    assert masking.parse_mask_spec('a', 'redact') == ('a', 'redact')


@pytest.mark.parametrize('value,method,expected', [
    ('alice', 'redact', '***'),
    ('4111111111111111', 'partial', '************1111'),
    ('abc', 'partial', '***'),
    ('203.0.113.77', 'ip_truncate', '203.0.113.0'),
    ('2001:db8:1:2:3:4:5:6', 'ip_truncate', '2001:db8:1::'),
    ('not-an-ip', 'ip_truncate', '***'),
])
def test_mask_value(value, method, expected):
    assert masking.mask_value(value, method) == expected


def test_hash_is_keyed_and_stable():
    a = masking.mask_value('alice', 'hash', 'salt1')
    assert a == masking.mask_value('alice', 'hash', 'salt1')
    assert a != masking.mask_value('alice', 'hash', 'salt2')
    assert a != masking.mask_value('bob', 'hash', 'salt1')
    assert a.startswith('masked:') and 'alice' not in a


def test_mask_record_nested_list_and_message():
    record = {
        'user': {'name': 'alice', 'id': ''},
        'related': {'user': ['alice', 'bob'], 'ip': ['203.0.113.7']},
        'a.b': 'dotted-key-value',
        'items': [{'secret': 'one-secret'}, {'secret': 'two-secret'}],
        '@message': ('{"u": "alice", "ip": "203.0.113.7", '
                     '"k": "dotted-key-value"}'),
    }
    count = masking.mask_record(
        record,
        ['user.name:redact', 'user.id', 'related.user:redact',
         'related.ip:ip_truncate', 'a.b:redact', 'items.secret:redact',
         'missing.field'])
    assert count == 7
    assert record['user'] == {'name': '***', 'id': ''}
    assert record['related'] == {'user': ['***', '***'],
                                 'ip': ['203.0.113.0']}
    assert record['a.b'] == '***'
    assert [i['secret'] for i in record['items']] == ['***', '***']
    assert 'alice' not in record['@message']
    assert '203.0.113.7' not in record['@message']
    assert 'dotted-key-value' not in record['@message']


def test_is_sampled():
    assert masking.is_sampled('x', 100)
    assert not masking.is_sampled('x', 0)
    ids = [f'id-{i}' for i in range(2000)]
    kept = sum(masking.is_sampled(i, 10) for i in ids)
    assert 100 < kept < 300
    # deterministic
    assert [masking.is_sampled(i, 10) for i in ids[:50]] == [
        masking.is_sampled(i, 10) for i in ids[:50]]


# integration with the parser
@pytest.fixture
def logconfig_overrides():
    return {}


@pytest.fixture
def create_logconfig(create_logconfig, logconfig_overrides):
    def _create(logtype):
        config = dict(create_logconfig(logtype))
        config.update(logconfig_overrides)
        return config
    return _create


def _run(parse_json_log):
    return parse_json_log(
        load_fixture('cloudtrail_network_activity.json'), 'cloudtrail', CT_KEY)


def test_default_does_not_change_anything(parse_json_log):
    results = _run(parse_json_log)
    assert len(results) == 2
    assert results[0]['doc']['user']['name'] == 'alice'


@pytest.mark.parametrize('logconfig_overrides', [{
    'mask_fields': ['user.name', 'source.ip:ip_truncate',
                    'related.ip:ip_truncate',
                    'userIdentity.accessKeyId:redact'],
    'mask_method': 'hash', 'mask_salt': 'test-salt'}])
def test_masking_in_parser(parse_json_log, logconfig_overrides):
    results = _run(parse_json_log)
    assert len(results) == 2
    doc = results[1]['doc']
    assert doc['user']['name'].startswith('masked:')
    assert doc['source']['ip'] == '203.0.113.0'
    assert doc['related']['ip'] == ['203.0.113.0']
    assert doc['userIdentity']['accessKeyId'] == '***'
    # masked values are also removed from the raw log
    message = doc['@message']
    for secret in ('203.0.113.5', 'AKIAIOSFODNN7EXAMPLE'):
        assert secret not in message
    # the document ID does not change by masking
    assert results[1]['id'] == '11111111-2222-3333-4444-555555555556'
    json.dumps(doc)


def _parsers(create_logconfig, logtype='cloudtrail'):
    """return LogParser objects, to look at is_ignored"""
    import gzip
    import io
    from types import SimpleNamespace

    import siem
    from siem import utils
    from siem.fileformat_json import FileFormatJson
    from conftest import _Disabled

    logconfig = create_logconfig(logtype)
    raw = load_fixture('cloudtrail_network_activity.json')
    rawdata = io.TextIOWrapper(
        io.BytesIO(gzip.decompress(gzip.compress(raw.encode()))))
    fileformat = FileFormatJson(rawdata, logconfig, logtype)
    logfile = SimpleNamespace(
        logtype=logtype, s3key=CT_KEY, s3bucket='test-bucket',
        file_format='json', accountid='111122223333', region='us-east-1',
        via_firelens=False, error_logs_count=0)
    sf_module = utils.load_sf_module(logfile, logconfig, [])
    parsers = []
    for lograw, logdict, logmeta in fileformat.extract_log(1, 100):
        parser = siem.LogParser(logfile, logconfig, sf_module,
                                _Disabled(), _Disabled(), _Disabled())
        parser(lograw, logdict, logmeta)
        parsers.append(parser)
    return parsers


@pytest.mark.parametrize('logconfig_overrides', [
    {'index_enabled': False}])
def test_s3_only_log_type(create_logconfig, logconfig_overrides):
    parsers = _parsers(create_logconfig)
    assert len(parsers) == 2
    assert all(p.is_ignored for p in parsers)
    assert 'kept in S3 only' in parsers[0].ignored_reason


@pytest.mark.parametrize('logconfig_overrides', [{'sampling_percent': 0}])
def test_sampling_zero_drops_all(create_logconfig, logconfig_overrides):
    parsers = _parsers(create_logconfig)
    assert all(p.is_ignored for p in parsers)
    assert 'sampling_percent' in parsers[0].ignored_reason


@pytest.mark.parametrize('logconfig_overrides', [{'sampling_percent': 100}])
def test_sampling_100_keeps_all(create_logconfig, logconfig_overrides):
    parsers = _parsers(create_logconfig)
    assert not any(p.is_ignored for p in parsers)


def test_index_enabled_default_in_ini(etl_config):
    for section in etl_config.sections():
        assert etl_config[section].getboolean('index_enabled') is True
        assert etl_config[section].getint('sampling_percent') == 100
        assert etl_config[section]['mask_fields'] == ''
