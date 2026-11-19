# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Optional detection content for Amazon OpenSearch Service domains.

* Security Analytics detector with the pre-packaged CloudTrail rules
* Industry packs: Sigma rules in detections/<pack>/*.yml, which are loaded
  as custom rules and run by a detector for each pack

Security Analytics is not available on OpenSearch Serverless.
APIs: https://docs.opensearch.org/latest/security-analytics/api-tools/
Every function here is best effort: the caller must not fail the
deployment because of an error.
"""
import json
import logging
import os
import re

logger = logging.getLogger(__name__)

SA_PATH = '_plugins/_security_analytics'
DETECTIONS_DIR = os.path.join(os.path.dirname(__file__), 'detections')
PACKS = ('finance', 'healthcare')
CLOUDTRAIL_INDEX_PATTERN = 'log-aws-cloudtrail-*'
CLOUDTRAIL_TOPIC = 'cloudtrail'
RE_TITLE = re.compile(r'^title:\s*(.+?)\s*$', re.MULTILINE)
SIGMA_HEADERS = {'Content-Type': 'application/json'}


def parse_packs(value):
    """'finance, healthcare' -> ['finance', 'healthcare'] (known packs only)"""
    packs = []
    for item in re.split(r'[\s,]+', str(value or '')):
        item = item.strip().lower()
        if not item:
            continue
        if item not in PACKS:
            logger.warning(f'unknown detection pack: {item}')
            continue
        if item not in packs:
            packs.append(item)
    return packs


def load_pack_rules(pack, base_dir=DETECTIONS_DIR):
    """Return a list of (file name, Sigma YAML text) of a pack"""
    pack_dir = os.path.join(base_dir, pack)
    rules = []
    for name in sorted(os.listdir(pack_dir)):
        if name.endswith('.yml'):
            with open(os.path.join(pack_dir, name), encoding='utf-8') as f:
                rules.append((name, f.read()))
    return rules


def rule_title(sigma_text):
    m = RE_TITLE.search(sigma_text)
    return m.group(1).strip('\'"') if m else None


def detector_name(kind):
    # 5-50 characters of letters, digits, hyphens, spaces and underscores
    return f'aes-siem-{kind}'


def build_detector(name, rule_topic, indices, pre_packaged_ids=(),
                   custom_ids=()):
    """Request body of Create detector"""
    return {
        'type': 'detector',
        'name': name,
        'detector_type': rule_topic,
        'enabled': True,
        'schedule': {'period': {'interval': 5, 'unit': 'MINUTES'}},
        'inputs': [{
            'detector_input': {
                'description': 'Created by SIEM on Amazon OpenSearch Service',
                'indices': list(indices),
                'custom_rules': [{'id': i} for i in custom_ids],
                'pre_packaged_rules': [{'id': i} for i in pre_packaged_ids],
            }
        }],
        'triggers': [{
            'name': 'aes-siem-high-and-critical',
            'severity': '1',
            'types': [rule_topic],
            'ids': [],
            'sev_levels': ['high', 'critical'],
            'tags': [],
            'actions': [],
        }],
    }


class SecurityAnalytics(object):
    """request(method, path, **kwargs) returns an object that has
    status_code, text and json()"""

    def __init__(self, request):
        self.request = request

    def _json(self, response):
        try:
            return response.json()
        except ValueError:
            return {}

    def index_exists(self, pattern):
        response = self.request(
            'GET', f'_cat/indices/{pattern}?format=json&h=index')
        if response.status_code != 200:
            return False
        return len(self._json(response)) > 0

    def _search(self, path, body):
        response = self.request('POST', path, json=body)
        if response.status_code != 200:
            logger.warning(f'{path}: {response.status_code} '
                           f'{response.text[:300]}')
            return []
        return self._json(response).get('hits', {}).get('hits', [])

    def find_custom_rule(self, category, title):
        body = {'from': 0, 'size': 100, 'query': {'nested': {
            'path': 'rule', 'query': {'bool': {'must': [
                {'match': {'rule.category': category}},
                {'match_phrase': {'rule.title': title}}]}}}}}
        hits = self._search(f'{SA_PATH}/rules/_search?pre_packaged=false',
                            body)
        for hit in hits:
            if hit.get('_source', {}).get('title') == title:
                return hit['_id']
        return None

    def ensure_custom_rule(self, category, sigma_text):
        """Create a custom rule if there is no rule with the same title.
        Return the ID of the rule, or None."""
        title = rule_title(sigma_text)
        if not title:
            logger.warning('a Sigma rule has no title')
            return None
        rule_id = self.find_custom_rule(category, title)
        if rule_id:
            return rule_id
        response = self.request(
            'POST', f'{SA_PATH}/rules?category={category}',
            data=sigma_text.encode('utf-8'), headers=SIGMA_HEADERS)
        if response.status_code != 200:
            logger.warning(f'failed to create rule {title}: '
                           f'{response.status_code} {response.text[:300]}')
            return None
        return self._json(response).get('_id')

    def prepackaged_rule_ids(self, category):
        body = {'from': 0, 'size': 10000, 'query': {'nested': {
            'path': 'rule', 'query': {'bool': {'must': [
                {'match': {'rule.category': category}}]}}}}}
        hits = self._search(f'{SA_PATH}/rules/_search?pre_packaged=true',
                            body)
        return [h['_id'] for h in hits
                if h.get('_source', {}).get('category') == category]

    def ensure_mappings(self, index_name, rule_topic):
        """Create the default field alias mappings of the log type"""
        response = self.request(
            'GET', f'{SA_PATH}/mappings/view',
            json={'index_name': index_name, 'rule_topic': rule_topic})
        if response.status_code != 200:
            logger.warning(f'mappings view: {response.status_code} '
                           f'{response.text[:300]}')
            return False
        properties = self._json(response).get('properties', {})
        response = self.request(
            'POST', f'{SA_PATH}/mappings',
            json={'index_name': index_name, 'rule_topic': rule_topic,
                  'partial': True,
                  'alias_mappings': {'properties': properties}})
        if response.status_code != 200:
            logger.warning(f'mappings: {response.status_code} '
                           f'{response.text[:300]}')
            return False
        return True

    def detector_exists(self, name):
        body = {'size': 100, 'query': {'nested': {
            'path': 'detector', 'query': {'bool': {'must': [
                {'match_phrase': {'detector.name': name}}]}}}}}
        hits = self._search(f'{SA_PATH}/detectors/_search', body)
        return any(h.get('_source', {}).get('name') == name for h in hits)

    def ensure_detector(self, name, rule_topic, indices,
                        pre_packaged_ids=(), custom_ids=()):
        """Create a detector if there is none with the name. A detector that
        exists is never changed, because users may have edited it."""
        if self.detector_exists(name):
            return 'exists'
        if not pre_packaged_ids and not custom_ids:
            return 'no rules'
        response = self.request(
            'POST', f'{SA_PATH}/detectors',
            json=build_detector(name, rule_topic, indices, pre_packaged_ids,
                                custom_ids))
        if response.status_code != 201 and response.status_code != 200:
            logger.warning(f'failed to create detector {name}: '
                           f'{response.status_code} {response.text[:300]}')
            return 'failed'
        return 'created'


def setup_detection_content(request, enable_detectors, packs,
                            base_dir=DETECTIONS_DIR):
    """Create detectors and rules. Return a dict of results. Never raises."""
    results = {}
    if not enable_detectors and not packs:
        return results
    try:
        sa = SecurityAnalytics(request)
        if not sa.index_exists(CLOUDTRAIL_INDEX_PATTERN):
            msg = (f'no index of {CLOUDTRAIL_INDEX_PATTERN} yet. Detectors '
                   f'are created when this function runs after CloudTrail '
                   f'logs are loaded')
            logger.info(msg)
            return {'skipped': msg}
        sa.ensure_mappings(CLOUDTRAIL_INDEX_PATTERN, CLOUDTRAIL_TOPIC)
        if enable_detectors:
            ids = sa.prepackaged_rule_ids(CLOUDTRAIL_TOPIC)
            results['cloudtrail'] = sa.ensure_detector(
                detector_name('cloudtrail'), CLOUDTRAIL_TOPIC,
                [CLOUDTRAIL_INDEX_PATTERN], pre_packaged_ids=ids)
        for pack in packs:
            custom_ids = []
            for _, sigma_text in load_pack_rules(pack, base_dir):
                rule_id = sa.ensure_custom_rule(CLOUDTRAIL_TOPIC, sigma_text)
                if rule_id:
                    custom_ids.append(rule_id)
            results[pack] = sa.ensure_detector(
                detector_name(f'pack-{pack}'), CLOUDTRAIL_TOPIC,
                [CLOUDTRAIL_INDEX_PATTERN], custom_ids=custom_ids)
    except Exception:
        logger.exception('failed to set up detection content')
        results['error'] = 'see the log'
    logger.info(json.dumps(results))
    return results
