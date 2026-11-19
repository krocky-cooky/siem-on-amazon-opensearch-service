# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Security Analytics detectors and the industry packs of Sigma rules.

The API calls follow
https://docs.opensearch.org/latest/security-analytics/api-tools/
They were not run against a real domain.
"""
import json
import os
import re
import sys
import uuid

import pytest
import yaml

DEPLOY_ES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'lambda', 'deploy_es')
sys.path.insert(0, DEPLOY_ES_DIR)
import detections  # noqa: E402

LEVELS = ('informational', 'low', 'medium', 'high', 'critical')


# Sigma rules
def _all_rules():
    for pack in detections.PACKS:
        for name, text in detections.load_pack_rules(pack):
            yield pack, name, text


def test_two_packs_with_rules():
    assert len(detections.PACKS) >= 2
    for pack in detections.PACKS:
        assert len(detections.load_pack_rules(pack)) >= 5


@pytest.mark.parametrize('pack,name,text', list(_all_rules()))
def test_sigma_rule_is_valid(pack, name, text):
    rule = yaml.safe_load(text)
    for key in ('title', 'id', 'status', 'description', 'logsource',
                'detection', 'level', 'tags', 'falsepositives'):
        assert rule.get(key), f'{pack}/{name} has no {key}'
    uuid.UUID(rule['id'])
    assert rule['level'] in LEVELS
    assert rule['logsource'] == {'product': 'aws', 'service': 'cloudtrail'}
    detection = rule['detection']
    condition = detection['condition']
    names = [k for k in detection if k != 'condition']
    assert names
    for ref in re.findall(r'[a-z_]+', condition):
        if ref not in ('and', 'or', 'not', '1', 'of', 'them'):
            assert ref in names, f'{pack}/{name}: {ref} is not defined'
    # the title of the file is found by detections.rule_title
    assert detections.rule_title(text) == rule['title']
    # Sigma title: 256 characters or less, and not empty
    assert 0 < len(rule['title']) <= 256


def test_rule_ids_and_titles_are_unique():
    ids, titles = [], []
    for _, _, text in _all_rules():
        rule = yaml.safe_load(text)
        ids.append(rule['id'])
        titles.append(rule['title'])
    assert len(set(ids)) == len(ids)
    assert len(set(titles)) == len(titles)


def test_rules_use_fields_of_cloudtrail_logs(parse_json_log):
    """Fields of the rules exist in a parsed CloudTrail document"""
    from conftest import load_fixture
    results = parse_json_log(
        load_fixture('cloudtrail_signin.json'), 'cloudtrail',
        'AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/01/x.json.gz')
    failed = next(r['doc'] for r in results
                  if r['doc']['responseElements'] == {
                      'ConsoleLogin': 'Failure'})
    # eventSource, eventName, responseElements.* and
    # additionalEventData.* are stored as they are in the log
    assert failed['eventSource'] == 'signin.amazonaws.com'
    assert failed['eventName'] == 'ConsoleLogin'
    assert failed['additionalEventData']['MFAUsed'] == 'No'
    assert failed['userIdentity']['type'] == 'IAMUser'


# helpers
@pytest.mark.parametrize('value,expected', [
    ('', []),
    (None, []),
    ('finance', ['finance']),
    ('finance, healthcare', ['finance', 'healthcare']),
    ('healthcare,healthcare', ['healthcare']),
    ('unknown,finance', ['finance']),
])
def test_parse_packs(value, expected):
    assert detections.parse_packs(value) == expected


def test_detector_names_follow_the_api_rule():
    for kind in ('cloudtrail', 'pack-finance', 'pack-healthcare'):
        name = detections.detector_name(kind)
        assert 5 <= len(name) <= 50
        assert re.fullmatch(r'[A-Za-z0-9\-_ ]+', name)


def test_build_detector():
    body = detections.build_detector(
        'aes-siem-cloudtrail', 'cloudtrail', ['log-aws-cloudtrail-*'],
        pre_packaged_ids=['p1'], custom_ids=['c1'])
    assert body['detector_type'] == 'cloudtrail'
    assert body['enabled'] is True
    detector_input = body['inputs'][0]['detector_input']
    # only one entry is supported
    assert detector_input['indices'] == ['log-aws-cloudtrail-*']
    assert detector_input['pre_packaged_rules'] == [{'id': 'p1'}]
    assert detector_input['custom_rules'] == [{'id': 'c1'}]
    trigger = body['triggers'][0]
    assert 5 <= len(trigger['name']) <= 50
    assert trigger['sev_levels'] == ['high', 'critical']
    json.dumps(body)


# API calls with a fake domain
class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class FakeDomain:
    def __init__(self, indices=('log-aws-cloudtrail-2026-10',),
                 custom_rules=None, detectors=None):
        self.indices = list(indices)
        self.custom_rules = dict(custom_rules or {})
        self.detectors = list(detectors or [])
        self.calls = []

    def __call__(self, method, path, headers=None, **kwargs):
        self.calls.append((method, path, kwargs, headers))
        if path.startswith('_cat/indices'):
            return FakeResponse(200, [{'index': i} for i in self.indices])
        if path.startswith('_plugins/_security_analytics/rules/_search'):
            if 'pre_packaged=true' in path:
                return FakeResponse(200, {'hits': {'hits': [
                    {'_id': 'pre1', '_source': {'category': 'cloudtrail'}},
                    {'_id': 'pre2', '_source': {'category': 'cloudtrail'}},
                    {'_id': 'pre3', '_source': {'category': 'windows'}}]}})
            return FakeResponse(200, {'hits': {'hits': [
                {'_id': i, '_source': {'title': t}}
                for t, i in self.custom_rules.items()]}})
        if path.startswith('_plugins/_security_analytics/rules?category='):
            title = detections.rule_title(kwargs['data'].decode())
            rule_id = f'custom-{len(self.custom_rules) + 1}'
            self.custom_rules[title] = rule_id
            return FakeResponse(200, {'_id': rule_id})
        if path == '_plugins/_security_analytics/mappings/view':
            return FakeResponse(200, {'properties': {
                'a': {'type': 'alias', 'path': 'eventName'}}})
        if path == '_plugins/_security_analytics/mappings':
            return FakeResponse(200, {'acknowledged': True})
        if path == '_plugins/_security_analytics/detectors/_search':
            return FakeResponse(200, {'hits': {'hits': [
                {'_id': 'd', '_source': {'name': n}}
                for n in self.detectors]}})
        if path == '_plugins/_security_analytics/detectors':
            self.detectors.append(kwargs['json']['name'])
            return FakeResponse(201, {'_id': 'new'})
        raise AssertionError(f'unexpected call {method} {path}')

    def posted(self, path):
        return [c for c in self.calls if c[0] == 'POST' and c[1] == path]


def test_nothing_is_called_when_disabled():
    domain = FakeDomain()
    assert detections.setup_detection_content(domain, False, []) == {}
    assert domain.calls == []


def test_skips_without_cloudtrail_index():
    domain = FakeDomain(indices=())
    result = detections.setup_detection_content(domain, True, ['finance'])
    assert 'skipped' in result
    assert not domain.posted('_plugins/_security_analytics/detectors')


def test_detector_with_prepackaged_rules():
    domain = FakeDomain()
    result = detections.setup_detection_content(domain, True, [])
    assert result == {'cloudtrail': 'created'}
    body = domain.posted('_plugins/_security_analytics/detectors')[0][2][
        'json']
    rules = body['inputs'][0]['detector_input']['pre_packaged_rules']
    # only rules of the CloudTrail category
    assert rules == [{'id': 'pre1'}, {'id': 'pre2'}]
    assert domain.posted('_plugins/_security_analytics/mappings')


def test_packs_create_rules_and_detectors():
    domain = FakeDomain()
    result = detections.setup_detection_content(
        domain, False, ['finance', 'healthcare'])
    assert result == {'finance': 'created', 'healthcare': 'created'}
    assert len(domain.custom_rules) == sum(
        len(detections.load_pack_rules(p)) for p in detections.PACKS)
    created = [c for c in domain.calls if '/rules?category=' in c[1]]
    assert all(c[1].endswith('category=cloudtrail') for c in created)
    assert all(c[3] == detections.SIGMA_HEADERS for c in created)
    names = domain.detectors
    assert 'aes-siem-pack-finance' in names
    assert 'aes-siem-pack-healthcare' in names


def test_second_run_changes_nothing():
    domain = FakeDomain()
    detections.setup_detection_content(domain, True, ['finance'])
    count = len(domain.detectors)
    rules = dict(domain.custom_rules)
    calls_before = len(domain.calls)
    result = detections.setup_detection_content(domain, True, ['finance'])
    assert result == {'cloudtrail': 'exists', 'finance': 'exists'}
    assert len(domain.detectors) == count
    assert domain.custom_rules == rules
    created = [c for c in domain.calls[calls_before:]
               if c[0] == 'POST' and (
                   c[1].endswith('detectors')
                   or '/rules?category=' in c[1])]
    assert created == []


def test_errors_do_not_raise():
    def broken(method, path, headers=None, **kwargs):
        raise RuntimeError('boom')
    result = detections.setup_detection_content(broken, True, ['finance'])
    assert result == {'error': 'see the log'}


def test_failed_api_calls_are_reported_not_raised():
    class Denied(FakeDomain):
        def __call__(self, method, path, headers=None, **kwargs):
            if path == '_plugins/_security_analytics/detectors':
                return FakeResponse(403, {'error': 'denied'})
            return super().__call__(method, path, headers, **kwargs)
    result = detections.setup_detection_content(Denied(), True, [])
    assert result == {'cloudtrail': 'failed'}
