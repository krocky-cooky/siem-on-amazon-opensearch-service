# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CloudTrail network activity events and WAF labels / CAPTCHA fields.

Samples are built from
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-network-events-with-cloudtrail.html
https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
"""
import pytest

from conftest import load_fixture

CT_KEY = ('AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/01/'
          '111122223333_CloudTrail_us-east-1_20261001T0100Z_abc.json.gz')
WAF_KEY = ('AWSLogs/111122223333/WAFLogs/us-east-1/test-acl/2026/10/01/'
           '01/00/111122223333_waflogs_us-east-1_test-acl_x.log.gz')


@pytest.fixture
def cloudtrail(parse_json_log):
    results = parse_json_log(
        load_fixture('cloudtrail_network_activity.json'), 'cloudtrail',
        CT_KEY)
    return {r['doc']['eventCategory']: r for r in results}


def test_network_activity_has_own_index(cloudtrail):
    net = cloudtrail['NetworkActivity']
    assert net['index'].startswith('log-aws-cloudtrail-networkactivity')
    assert net['doc']['event']['category'] == ['network']
    assert net['doc']['event']['outcome'] == 'failure'
    assert net['doc']['vpcEndpointId'] == 'vpce-0123456789abcdef0'


def test_management_events_keep_index(cloudtrail):
    mgmt = cloudtrail['Management']
    assert mgmt['index'].startswith('log-aws-cloudtrail-')
    assert 'networkactivity' not in mgmt['index']
    assert mgmt['doc']['event']['category'] == ['iam']


def test_network_activity_index_matches_cloudtrail_template(cloudtrail):
    # the index pattern of the CloudTrail index template is
    # log-aws-cloudtrail-*, so the new index uses the same mappings
    import fnmatch
    assert fnmatch.fnmatch(cloudtrail['NetworkActivity']['index'],
                           'log-aws-cloudtrail-*')


@pytest.fixture
def waf_doc(parse_json_log):
    results = parse_json_log(
        load_fixture('waf_labels_captcha.json'), 'waf', WAF_KEY)
    assert len(results) == 1
    return results[0]['doc']


def test_waf_labels(waf_doc):
    assert waf_doc['waf_labels'] == [
        'awswaf:managed:aws:bot-control:bot:category:http_library',
        'custom:suspicious']


def test_waf_captcha_failure(waf_doc):
    assert waf_doc['event']['reason'] == 'TOKEN_MISSING'
    assert waf_doc['event']['outcome'] == 'failure'
    assert waf_doc['captchaResponse']['responseCode'] == 405
