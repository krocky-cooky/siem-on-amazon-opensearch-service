# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""VPC Flow Logs v5 to v9 fields (D-1, #454).

https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
"""
import configparser
import json
import os

import pytest

S3KEY = ('AWSLogs/111122223333/vpcflowlogs/us-east-1/2026/10/01/'
         '111122223333_vpcflowlogs_us-east-1_fl-0123_20261001T0000Z_abc.log')
HEADER = ('version account-id interface-id srcaddr dstaddr srcport dstport '
          'protocol packets bytes start end action log-status '
          'flow-direction traffic-path pkt-src-aws-service '
          'pkt-dst-aws-service ecs-cluster-name ecs-cluster-arn '
          'ecs-container-id ecs-task-id ecs-service-name reject-reason '
          'resource-id encryption-status')
ECS_ROW = ('9 111122223333 eni-0123 10.0.1.10 52.94.0.10 49152 443 6 10 '
           '8400 1790812740 1790812800 ACCEPT OK egress 8 - S3 '
           'web arn:aws:ecs:us-east-1:111122223333:cluster/web '
           'abcdef0123 0f1e2d3c4b5a web-svc - - 1')
BPA_ROW = ('9 111122223333 eni-0123 198.51.100.7 10.0.1.10 40000 22 6 1 '
           '60 1790812740 1790812800 REJECT OK ingress - - - - - - - - '
           'BPA nat-0abc 0')
DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')


@pytest.fixture
def docs(parse_csv_log):
    raw = '\n'.join([HEADER, ECS_ROW, BPA_ROW]) + '\n'
    results = parse_csv_log(raw, 'vpcflowlogs', S3KEY)
    assert len(results) == 2
    return [r['doc'] for r in results]


def test_v5_fields(docs):
    doc = docs[0]
    assert doc['network']['direction'] == 'egress'
    assert doc['traffic_path'] == '8'
    assert doc['pkt_dst_aws_service'] == 'S3'
    assert 'pkt_src_aws_service' not in doc


def test_v7_ecs_fields(docs):
    doc = docs[0]
    assert doc['container']['id'] == 'abcdef0123'
    assert doc['orchestrator']['type'] == 'ecs'
    assert doc['orchestrator']['cluster']['name'] == 'web'
    assert doc['orchestrator']['resource'] == {
        'name': '0f1e2d3c4b5a', 'type': 'task'}
    assert doc['ecs_service_name'] == 'web-svc'


def test_v8_reject_reason(docs):
    doc = docs[1]
    assert doc['event']['reason'] == 'BPA'
    assert doc['event']['outcome'] == 'failure'
    assert 'orchestrator' not in doc


def test_v9_fields(docs):
    assert docs[0]['encryption_status'] == '1'
    assert docs[1]['resource_id'] == 'nat-0abc'


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
def test_template(ini_name):
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, ini_name))
    template = json.loads(data['component-templates'][
        'component_template_log-aws-vpcflowlogs'])
    props = template['template']['mappings']['properties']
    assert props['encryption_status']['type'] == 'short'
    for field in ('ecs_cluster_arn', 'ecs_task_id', 'reject_reason',
                  'resource_id', 'pkt_src_aws_service', 'flow_direction'):
        assert props[field]['type'] == 'keyword'
    assert template['version'] == 3
