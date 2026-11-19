# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bedrock, VPC Lattice, Verified Access, Network Firewall TLS, sign-in
events and the generic CloudWatch vended log intake.

Samples are built from the AWS documentation:
https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
https://docs.aws.amazon.com/vpc-lattice/latest/ug/monitoring-access-logs.html
https://docs.aws.amazon.com/verified-access/latest/ug/ocsfv1-examples.html
https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-contents.html
The generic sample is synthetic and does not follow a real service format.
"""
import configparser
import json
import os
import re

import pytest

from conftest import load_fixture
from siem import utils

DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')


@pytest.mark.parametrize('s3key,logtype', [
    ('x/AWSLogs/111122223333/BedrockModelInvocationLogs/us-east-1/2026/10/01/'
     '12/20261001T1200Z_abc.json.gz', 'bedrock'),
    ('AWSLogs/123456789012/VPCLattice/service/svc-1a2b3c4d/2023/07/28/20/a.gz',
     'vpclattice'),
    ('AWSLogs/123456789012/vpclattice/service/svc-1/2023/07/28/20/a.gz',
     'vpclattice'),
    ('AWSLogs/111122223333/VerifiedAccess/us-east-1/2026/10/01/a.json.gz',
     'verifiedaccess'),
])
def test_s3key_detection(logtype_s3key_dict, s3key, logtype):
    assert utils.get_logtype_from_s3key(s3key, logtype_s3key_dict) == logtype


def test_vended_generic_is_disabled_by_default(logtype_s3key_dict):
    regex = logtype_s3key_dict['vended-generic']
    for key in ('AWSLogs/111122223333/Anything/a.json.gz', '', 'x'):
        assert not regex.search(key)
    assert utils.get_logtype_from_s3key(
        'AWSLogs/111122223333/Anything/a.json.gz',
        logtype_s3key_dict) == 'unknown'


# Bedrock
@pytest.fixture
def bedrock(parse_json_log):
    results = parse_json_log(
        load_fixture('bedrock_invocation.json'), 'bedrock',
        'AWSLogs/111122223333/BedrockModelInvocationLogs/us-east-1/a.json.gz')
    assert len(results) == 2
    return results


def test_bedrock_ecs(bedrock):
    doc = bedrock[0]['doc']
    assert bedrock[0]['index'].startswith('log-aws-bedrock-')
    assert bedrock[0]['id'] == 'abcd1234-5678-efgh-ijkl-000000000001'
    assert doc['cloud']['account']['id'] == '111122223333'
    assert doc['event']['action'] == 'Converse'
    assert doc['user']['name'] == 'session-name'
    assert doc['user']['id'].startswith('arn:aws:sts::')
    assert doc['input']['inputTokenCount'] == 25
    assert doc['output']['outputTokenCount'] == 150
    assert doc['@timestamp'].startswith('2026-10-01T12:00:00')


def test_bedrock_bodies_are_text(bedrock):
    # the body depends on the model, so it is loaded as text
    for r in bedrock:
        assert isinstance(r['doc']['input']['inputBodyJson'], str)
        assert isinstance(r['doc']['output']['outputBodyJson'], str)
    assert bedrock[1]['doc']['user']['name'] == 'alice'


# VPC Lattice
@pytest.fixture
def lattice(parse_json_log):
    results = parse_json_log(
        load_fixture('vpclattice_access.json'), 'vpclattice',
        'AWSLogs/123456789012/VPCLattice/service/svc-1a2b3c4d/a.gz')
    assert len(results) == 3
    return [r['doc'] for r in results]


def test_lattice_access_log(lattice):
    doc = lattice[0]
    assert doc['source']['ip'] == '192.0.2.150'
    assert doc['source']['port'] == 80
    assert doc['destination']['ip'] == '198.51.100.44'
    assert doc['related']['ip'] == ['192.0.2.150', '198.51.100.44']
    assert str(doc['http']['response']['status_code']) == '200'
    assert doc['url']['path'] == '/billing'
    assert doc['cloud']['account']['id'] == '123456789012'
    assert doc['event']['outcome'] == 'success'
    assert 'reason' not in doc['event']
    assert 'id' not in doc.get('user', {})
    assert doc['@timestamp'].startswith('2023-07-28T20:48:45')


def test_lattice_denied_and_ipv6(lattice):
    doc = lattice[1]
    assert doc['source']['ip'] == '2001:db8::1'
    assert doc['source']['port'] == 44000
    assert 'destination' not in doc or 'ip' not in doc['destination']
    assert doc['event']['reason'] == 'ClientAccessDenied'
    assert doc['event']['outcome'] == 'failure'


def test_lattice_resource_access_log(lattice):
    doc = lattice[2]
    assert doc['source']['ip'] == '172.31.23.56'
    assert doc['destination']['ip'] == '10.0.18.190'
    assert doc['cloud']['account']['id'] == '123456789012'
    assert doc['@timestamp'].startswith('2024-12-02T10:10:10')


# Verified Access
def test_verified_access(parse_json_log):
    results = parse_json_log(
        load_fixture('verifiedaccess_ocsf.json'), 'verifiedaccess',
        'AWSLogs/111122223333/VerifiedAccess/us-east-1/a.json.gz')
    assert len(results) == 1
    assert results[0]['index'].startswith('log-aws-verifiedaccess-')
    doc = results[0]['doc']
    assert doc['source']['ip'] == '172.24.57.68'
    assert doc['url']['full'] == 'https://hello.app.example.com:443/'
    assert str(doc['http']['response']['status_code']) == '200'
    assert doc['user']['email'] == 'johndoe@example.com'
    assert doc['event']['action'] == 'Access Grant'
    assert doc['event']['outcome'] == 'success'
    assert doc['@timestamp'].startswith('2022-11-16T06:29:54')


# Network Firewall TLS events
def test_networkfirewall_tls_event(parse_json_log):
    results = parse_json_log(
        load_fixture('networkfirewall_tls.json'), 'networkfirewall',
        'AWSLogs/111122223333/network-firewall/tls/x_network-firewall_x.gz')
    assert len(results) == 2
    tls, alert = results[0]['doc'], results[1]['doc']
    assert tls['event']['module'] == 'tls'
    assert tls['event']['action'] == 'DROP'
    assert tls['event']['outcome'] == 'failure'
    assert tls['event']['reason'] == 'certificate revocation check: REVOKED'
    assert tls['url']['domain'] == 'revoked-rsa-dv.ssl.com'
    assert tls['destination']['ip'] == '54.92.160.72'
    # alert events are not changed
    assert alert['event']['kind'] == 'alert'
    assert alert['event']['category'] == 'intrusion_detection'


# sign-in events
def test_signin_events(parse_json_log):
    results = parse_json_log(
        load_fixture('cloudtrail_signin.json'), 'cloudtrail',
        'AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/01/x.json.gz')
    docs = {r['id']: r['doc'] for r in results}
    failed = docs['aaaaaaaa-0000-0000-0000-000000000001']
    assert failed['event']['category'] == ['authentication', 'iam']
    assert failed['event']['outcome'] == 'failure'
    sso = docs['aaaaaaaa-0000-0000-0000-000000000002']
    assert sso['event']['category'] == ['authentication', 'iam']
    assert sso['event']['outcome'] == 'success'
    ok = docs['aaaaaaaa-0000-0000-0000-000000000003']
    assert ok['event']['outcome'] == 'success'


# generic intake
def test_vended_generic(parse_json_log):
    results = parse_json_log(
        load_fixture('vended_generic_sample.json'), 'vended-generic',
        'AWSLogs/111122223333/MyService/us-east-1/a.json.gz')
    assert len(results) == 1
    doc = results[0]['doc']
    assert results[0]['index'].startswith('log-aws-vended-')
    assert doc['@timestamp'].startswith('2026-10-01T02:03:04')
    assert doc['cs_host'] == 'x.example.com'
    assert doc['eventtimestamp'] == '2026-10-01T02:03:04Z'


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
@pytest.mark.parametrize('index', ['bedrock', 'vpclattice', 'verifiedaccess',
                                   'vended'])
def test_index_templates_exist(ini_name, index):
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, ini_name))
    for section, key in (('index-templates', f'log-aws-{index}_aws'),
                         ('index-rollover', f'log-aws-{index}_rollover')):
        template = json.loads(data[section][key])
        assert re.fullmatch(r'log-aws-%s-.*' % index,
                            template['index_patterns'][0].replace('*', 'x'))
        for name in template['composed_of']:
            assert name in data['component-templates']
