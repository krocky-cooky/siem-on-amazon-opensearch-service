# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CloudFront standard logging (v2): JSON and W3C formats.

Samples follow the field names and the S3 path in
https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logging.html
"""
import io
from types import SimpleNamespace

import pytest

import siem
from siem import utils

from conftest import load_fixture

S3KEY = ('AWSLogs/111122223333/CloudFront/E1ABCDEF234567/2024/11/15/19/'
         'E1ABCDEF234567.2024-11-15-19.abcdef01.gz')


def test_normalize_field_name():
    f = utils.normalize_field_name
    assert f('cs(User-Agent)') == 'cs_user_agent'
    assert f('cs(Host)') == 'cs_host'
    assert f('x-edge-location') == 'x_edge_location'
    assert f('timestamp(ms)') == 'timestamp_ms'
    assert f('DistributionId') == 'distributionid'


def test_normalize_field_names_adds_date_time():
    d = utils.normalize_field_names({'date': '2024-11-15', 'time': '01:02:03'})
    assert d['date_time'] == '2024-11-15 01:02:03'


def test_s3key_detection(logtype_s3key_dict):
    get = utils.get_logtype_from_s3key
    assert get(S3KEY, logtype_s3key_dict) == 'cloudfront-v2'
    hive = ('AWSLogs/aws-account-id=111122223333/CloudFront/'
            'DistributionId=E1ABCDEF234567/year=2024/x.parquet')
    assert get(hive, logtype_s3key_dict) == 'cloudfront-v2'
    # legacy standard logs and real-time logs keep their log type, even
    # if the prefix in the documentation starts with AWSLogs/.../CloudFront/
    doc_standard = ('AWSLogs/111122223333/CloudFront/global/E1ABCDEF234567/'
                    'standard/E1ABCDEF234567.2024-11-15-19.abcdef01.gz')
    assert get(doc_standard, logtype_s3key_dict) == 'cloudfront-standard'
    doc_realtime = ('AWSLogs/111122223333/CloudFront/global/E1ABCDEF234567/'
                    'realtime/2024/11/15/19/file.gz')
    assert get(doc_realtime, logtype_s3key_dict) == 'cloudfront-realtime'
    legacy = 'cflogs/E1ABCDEF234567.2024-11-15-19.abcdef01.gz'
    assert get(legacy, logtype_s3key_dict) == 'cloudfront-standard'


@pytest.fixture
def json_docs(parse_json_log):
    results = parse_json_log(
        load_fixture('cloudfront_v2.json'), 'cloudfront-v2', S3KEY)
    assert len(results) == 2
    return [r['doc'] for r in results]


def test_json_ecs(json_docs):
    doc = json_docs[0]
    assert doc['source']['ip'] == '203.0.113.10'
    assert doc['source']['port'] == '54321' or doc['source']['port'] == 54321
    assert doc['http']['request']['method'] == 'GET'
    assert doc['url']['path'] == '/index.html'
    assert doc['url']['domain'] == 'www.example.com'
    assert doc['url']['full'] == 'https://www.example.com/index.html?a=1&b=2'
    assert doc['http']['version'] == '2.0'
    assert doc['user_agent']['original'] == 'Mozilla/5.0 (X11; Linux)'
    assert doc['distribution_id'] == 'E1ABCDEF234567'
    assert doc['@timestamp'].startswith('2024-11-15T19:45:51.183')


def test_json_without_optional_fields(json_docs):
    doc = json_docs[1]
    assert doc['http']['response']['status_code'] in (403, '403')
    assert doc['url']['full'] == 'https://www.example.com/login'
    # no DistributionId field: it is taken from the S3 key
    assert doc['distribution_id'] == 'E1ABCDEF234567'
    # no timestamp(ms): date and time are used
    assert doc['@timestamp'].startswith('2024-11-15T19:45:52')


def test_w3c_format(parse_csv_log):
    results = parse_csv_log(
        load_fixture('cloudfront_v2.w3c.txt'), 'cloudfront-v2', S3KEY)
    assert len(results) == 1
    doc = results[0]['doc']
    assert results[0]['index'].startswith('log-aws-cloudfront-')
    assert doc['source']['ip'] == '203.0.113.20'
    assert doc['url']['full'] == 'https://www.example.com/a.png?x=1'
    assert doc['user_agent']['original'] == 'curl/8.0'
    assert doc['@timestamp'].startswith('2024-11-14T22:30:25.421')


@pytest.mark.parametrize('text,expected_format', [
    ('#Fields: date time\n2024-11-14\t22:30:25\n', 'csv'),
    ('{"date": "2024-11-14"}\n', 'json'),
])
def test_w3c_is_detected_by_header(create_logconfig, text, expected_format):
    ns = SimpleNamespace(
        file_format='json', logtype='cloudfront-v2',
        logconfig=create_logconfig('cloudfront-v2'),
        rawdata=io.StringIO(text))
    ns._is_w3c_fields_header = (
        lambda: siem.LogS3._is_w3c_fields_header(ns))
    instance = siem.LogS3.set_rawfile_instance(ns)
    assert ns.file_format == expected_format
    assert instance.__class__.__name__.lower().startswith(
        'fileformat' + expected_format)
