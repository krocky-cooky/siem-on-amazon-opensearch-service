# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from aws_lambda_powertools import Logger

from siem import utils

logger = Logger(child=True)

RE_GD_TYPE = re.compile(
    r"(?P<ThreatPurpose>\w*):(?P<ResourceTypeAffected>\w*)/"
    r"(?P<ThreatFamilyName>[\w\&]*)(\.(?P<DetectionMechanism>\w*))?"
    r"(\!(?P<Artifact>\w*))?")

# Fields extracted from the finding type. Kept as a constant so that the
# fallback in transform() cannot drift from the parsed result.
GD_TYPE_KEYS = ('ThreatPurpose', 'ResourceTypeAffected', 'ThreatFamilyName',
                'DetectionMechanism', 'Artifact')


def _as_list(value):
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _unique(values):
    result = []
    for value in values:
        if value not in (None, '') and value not in result:
            result.append(value)
    return result


def _add_related(logdata, key, values):
    related = logdata.setdefault('related', {})
    related[key] = _unique(_as_list(related.get(key)) + values)
    if not related[key]:
        del related[key]


def expand_attack_sequence(logdata):
    """copy the key parts of an attack sequence to searchable fields.

    service.detection.sequence is stored as flat_object, so actors,
    endpoints and signals are copied to attack_sequence.* and related.*.
    https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Sequence.html
    """
    try:
        sequence = logdata['service']['detection']['sequence']
    except (KeyError, TypeError):
        return logdata
    if not isinstance(sequence, dict):
        return logdata

    def items(key):
        return [x for x in _as_list(sequence.get(key)) if isinstance(x, dict)]

    actors, endpoints = items('actors'), items('endpoints')
    signals, resources = items('signals'), items('resources')
    indicators = items('sequenceIndicators')

    users = [(a.get('user') or {}).get('name') for a in actors]
    ips = [e.get('ip') for e in endpoints]
    domains = [e.get('domain') for e in endpoints]

    summary = {
        'uid': sequence.get('uid'),
        'actor_ids': _unique(a.get('id') for a in actors),
        'endpoint_ips': _unique(ips),
        'endpoint_domains': _unique(domains),
        'resource_uids': _unique(r.get('uid') for r in resources),
        'signal_names': _unique(s.get('name') for s in signals),
        'signal_types': _unique(s.get('type') for s in signals),
        'signal_count': len(signals),
        'indicators': [{'key': i.get('key'),
                        'values': _unique(_as_list(i.get('values')))}
                       for i in indicators if i.get('key')],
    }
    logdata['attack_sequence'] = {
        k: v for k, v in summary.items() if v not in (None, '', [])}

    _add_related(logdata, 'ip', _unique(ips))
    _add_related(logdata, 'user', _unique(users))
    _add_related(logdata, 'hosts', _unique(domains))
    return logdata


def transform(logdata):
    logdata = expand_attack_sequence(logdata)
    logdata['rule']['name'] = logdata['rule']['name'].strip().rstrip('.')
    severity = logdata['severity']
    if severity <= 3.9:
        label = "low"
    elif severity <= 6.9:
        label = "medium"
    elif severity <= 8.9:
        label = "high"
    elif severity <= 10.0:
        label = "critical"
    else:
        logger.warning(
            f'GuardDuty severity {severity} is outside the documented '
            'range of 1.0-10.0. Labelled as unknown')
        label = "unknown"
    m = RE_GD_TYPE.match(logdata['type'])
    if m:
        gd_type = {key: m.group(key) for key in GD_TYPE_KEYS}
    else:
        # An unparsable finding type must not cost us the whole document.
        logger.warning(
            f"GuardDuty finding type is not parsable: {logdata['type']}")
        gd_type = dict.fromkeys(GD_TYPE_KEYS)
    gd = {'severitylabel': label, **gd_type}
    try:
        action_type = logdata['service']['action']['actionType']
    except KeyError:
        action_type = ''
    if action_type == 'NETWORK_CONNECTION':
        direction = (logdata['service']['action']
                     ['networkConnectionAction']['connectionDirection'])
    elif action_type == 'DNS_REQUEST':
        direction = "OUTBOUND"
    elif gd['ThreatFamilyName'] in ('SuspiciousFile', 'MaliciousFile'):
        direction = None
    else:
        direction = "INBOUND"
    if direction:
        gd['network'] = {'direction': direction.lower()}
    logdata = utils.merge_dicts(logdata, gd)
    if direction == "OUTBOUND":
        logdata['source'], logdata['destination'] = (
            logdata.get('destination'), logdata.get('source'))
        if not logdata['source']:
            del logdata['source']
        if not logdata['destination']:
            del logdata['destination']
    # event.category
    if gd['ThreatPurpose'] in ('Backdoor', 'CryptoCurrency', 'Trojan'):
        logdata['event']['category'] = 'malware'
    elif gd['ThreatFamilyName'] in ('SuspiciousFile', 'MaliciousFile'):
        logdata['event']['category'] = 'malware'
    return logdata
