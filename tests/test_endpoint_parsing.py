# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Region and service for SigV4 are read from the endpoint (#493).

OpenSearch Serverless NextGen endpoints are <id>.aoss.<region>.on.aws, so
the region is not the 2nd label as for domains and Classic collections.
"""
import ast
import os

import pytest

from siem import utils

LAMBDA_DIR = os.path.join(os.path.dirname(__file__), '..', 'source', 'lambda')

CASES = [
    ('search-aes-siem-abc.us-east-1.es.amazonaws.com', 'us-east-1', 'es'),
    ('vpc-aes-siem-abc.ap-northeast-1.es.amazonaws.com',
     'ap-northeast-1', 'es'),
    ('vpc-aes-siem-abc.cn-north-1.es.amazonaws.com.cn', 'cn-north-1', 'es'),
    ('abc123.us-east-1.aoss.amazonaws.com', 'us-east-1', 'aoss'),
    ('abc123.aoss.ap-northeast-1.on.aws', 'ap-northeast-1', 'aoss'),
    ('123456789012.aoss.us-west-2.on.aws', 'us-west-2', 'aoss'),
]


def _function_from(path, name):
    with open(path) as f:
        tree = ast.parse(f.read())
    node = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == name)
    namespace = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, 'exec'),
         namespace)
    return namespace[name]


def _deploy_es_service(endpoint):
    """run the AOS_SERVICE block of deploy_es/index.py"""
    path = os.path.join(LAMBDA_DIR, 'deploy_es', 'index.py')
    with open(path) as f:
        tree = ast.parse(f.read())
    node = next(n for n in tree.body if isinstance(n, ast.If)
                and 'ENDPOINT' in ast.unparse(n.test)
                and 'AOS_SERVICE' in ast.unparse(n))
    namespace = {'ENDPOINT': endpoint, 'DEPLOYMENT_TARGET': ''}
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, 'exec'),
         namespace)
    return namespace['AOS_SERVICE']


@pytest.mark.parametrize('host, region, service', CASES)
def test_es_loader(host, region, service):
    assert utils.parse_endpoint(host) == (region, service)


@pytest.mark.parametrize('host, region, service', CASES)
def test_index_metrics_exporter(host, region, service):
    parse = _function_from(
        os.path.join(LAMBDA_DIR, 'index_metrics_exporter', 'index.py'),
        'parse_endpoint')
    assert parse(host) == (region, service)


@pytest.mark.parametrize('host, region, service', CASES)
def test_deploy_es(host, region, service):
    assert _deploy_es_service(host) == service
