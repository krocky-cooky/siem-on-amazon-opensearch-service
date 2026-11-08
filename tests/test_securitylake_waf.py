# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS WAFv2 logs from Security Lake: OCSF 4002 HTTP Activity (C-5)."""
import configparser
import json
import os

import pytest

from conftest import load_fixture

S3KEY = ('aws-security-data-lake-us-east-1-xxxx/ext/WAF/2.0/'
         'region=us-east-1/accountId=111122223333/eventDay=20260920/'
         '0123456789abcdef0123456789abcdef.gz.parquet')
DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')


@pytest.fixture
def waf_doc(parse_json_log):
    results = parse_json_log(
        load_fixture('securitylake_waf_http_activity.json'),
        'securitylake', S3KEY)
    assert len(results) == 1
    return results[0]


def test_index_name(waf_doc):
    assert waf_doc['index'].startswith('log-ocsf-network-')
    assert waf_doc['doc']['@log_type'] == 'ocsf-network-activity'


def test_ecs_http_fields(waf_doc):
    doc = waf_doc['doc']
    assert doc['http']['request']['method'] == 'GET'
    assert doc['http']['request']['referrer'] == 'https://example.com/'
    assert int(doc['http']['response']['status_code']) == 403
    assert doc['url']['domain'] == 'www.example.com'
    assert doc['url']['path'] == '/admin'
    assert doc['url']['query'] == 'id=1'
    assert doc['url']['full'] == '/admin?id=1'


def test_ecs_rule_and_source(waf_doc):
    doc = waf_doc['doc']
    assert doc['rule']['name'] == 'AWS-AWSManagedRulesCommonRuleSet'
    assert doc['source']['ip'] == '198.51.100.10'
    assert doc['user_agent']['original'] == 'curl/8.0.1'


def test_unmapped_is_text(waf_doc):
    assert isinstance(waf_doc['doc']['unmapped'], str)


@pytest.mark.parametrize('ini_name', ['data.ini', 'data-serverless.ini'])
def test_http_activity_mapping(ini_name):
    data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    data.read(os.path.join(DEPLOY_ES_DIR, ini_name))
    template = json.loads(
        data['component-templates']['component_template_log-ocsf'])
    props = template['template']['mappings']['properties']
    assert props['http_response']['properties']['code']['type'] == 'integer'
    assert props['firewall_rule']['properties']['name']['type'] == 'keyword'
    assert props['http_status']['type'] == 'integer'
    assert props['action']['type'] == 'keyword'
