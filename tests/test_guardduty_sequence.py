# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""GuardDuty attack sequences (D-2) and new protection plans (D-3)."""
import configparser
import json
import os

import pytest

from conftest import load_fixture

S3KEY = ('AWSLogs/111122223333/GuardDuty/us-east-1/2026/10/01/'
         'abc.jsonl.gz')
DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')


@pytest.fixture
def findings(parse_json_log):
    results = parse_json_log(
        load_fixture('guardduty_attack_sequence.json'), 'guardduty', S3KEY)
    return {r['doc']['id']: r['doc'] for r in results}


def test_sequence_summary(findings):
    seq = findings['seq-0001']['attack_sequence']
    assert seq['uid'] == 'seq-uid-1'
    assert seq['actor_ids'] == ['actor-1']
    assert seq['endpoint_ips'] == ['198.51.100.20']
    assert seq['endpoint_domains'] == ['bad.example.com']
    assert seq['signal_names'] == ['CryptoCurrency:Runtime/BitcoinTool.B',
                                   'ecs:RunTask']
    assert seq['signal_types'] == ['FINDING', 'API']
    assert seq['signal_count'] == 2
    assert seq['indicators'] == [
        {'key': 'ATTACK_TACTIC', 'values': ['Impact', 'Execution']}]


def test_sequence_related(findings):
    doc = findings['seq-0001']
    assert '198.51.100.20' in doc['related']['ip']
    assert doc['related']['user'] == ['alice']
    assert doc['related']['hosts'] == ['bad.example.com']
    assert doc['severitylabel'] == 'critical'
    assert doc['ThreatPurpose'] == 'AttackSequence'


def test_runtime_monitoring_container(findings):
    doc = findings['rt-0001']
    assert doc['container']['id'] == 'abcdef0123'
    assert doc['container']['name'] == 'app'
    assert doc['container']['runtime'] == 'containerd'
    assert doc['container']['image']['name'].endswith('/app:1.0')
    assert doc['orchestrator']['cluster']['name'] == 'web'
    assert 'attack_sequence' not in doc


def test_custom_detection_type(findings):
    gd = findings['cu-0001']
    assert gd['ThreatFamilyName'] == 'MaliciousDomainRequest'
    assert gd['DetectionMechanism'] == 'Custom'


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
def test_template(ini_name):
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, ini_name))
    template = json.loads(data['component-templates'][
        'component_template_log-aws-guardduty'])
    props = template['template']['mappings']['properties']
    assert props['attack_sequence.endpoint_ips']['type'] == 'ip'
    assert props['attack_sequence.signal_names']['type'] == 'keyword'
    assert template['version'] == 4
