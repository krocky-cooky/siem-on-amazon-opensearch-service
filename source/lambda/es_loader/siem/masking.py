# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Field masking and sampling before documents are indexed.

All functions are pure so that they can be tested without AWS.
"""
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import hashlib
import hmac
import ipaddress

METHODS = ('hash', 'redact', 'partial', 'ip_truncate')
REDACTED = '***'
# values shorter than this are not replaced in @message, to avoid
# replacing unrelated parts of the raw log
MIN_LENGTH_IN_MESSAGE = 3


def parse_mask_spec(spec, default_method='hash'):
    """'source.ip:ip_truncate' -> ('source.ip', 'ip_truncate')"""
    field, sep, method = spec.rpartition(':')
    if sep and method in METHODS:
        return field, method
    return spec, default_method


def mask_value(value, method, salt=''):
    """Return the masked value. The type of the result is str, except for
    ip_truncate of a valid IP address, which is still a valid IP address.
    """
    text = str(value)
    if method == 'redact':
        return REDACTED
    if method == 'partial':
        if len(text) <= 4:
            return REDACTED
        return '*' * (len(text) - 4) + text[-4:]
    if method == 'ip_truncate':
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return REDACTED
        prefix = 24 if ip.version == 4 else 48
        net = ipaddress.ip_network(f'{ip}/{prefix}', strict=False)
        return str(net.network_address)
    # hash: keyed hash, so that the same value gets the same result
    digest = hmac.new(salt.encode(), text.encode(), hashlib.sha256)
    return f'masked:{digest.hexdigest()[:16]}'


def _mask_path(node, parts, method, salt, originals):
    """Mask the value at dotted path parts in node (dict or list)."""
    if isinstance(node, list):
        for i, item in enumerate(node):
            if isinstance(item, (dict, list)):
                _mask_path(item, parts, method, salt, originals)
            elif not parts:
                masked = mask_value(item, method, salt)
                originals.append((item, masked))
                node[i] = masked
        return
    if not isinstance(node, dict) or not parts:
        return
    key = parts[0]
    # keys may contain dots, such as "requestParameters.x" in flat logs
    for n in range(len(parts), 0, -1):
        joined = '.'.join(parts[:n])
        if joined in node:
            key, rest = joined, parts[n:]
            break
    else:
        return
    value = node[key]
    if not rest:
        if value is None or value == '' or isinstance(value, dict):
            return
        if isinstance(value, list):
            _mask_path(value, [], method, salt, originals)
            return
        masked = mask_value(value, method, salt)
        originals.append((value, masked))
        node[key] = masked
    else:
        _mask_path(value, rest, method, salt, originals)


def mask_record(record, specs, default_method='hash', salt=''):
    """Mask fields of record in place and return the number of masked values.

    specs: list of 'dotted.field' or 'dotted.field:method'
    The raw log in @message is also masked.
    """
    originals = []
    for spec in specs:
        field, method = parse_mask_spec(spec, default_method)
        if not field:
            continue
        _mask_path(record, field.split('.'), method, salt, originals)
    message = record.get('@message')
    if isinstance(message, str):
        # replace long values first
        for original, masked in sorted(
                originals, key=lambda x: len(str(x[0])), reverse=True):
            text = str(original)
            if len(text) >= MIN_LENGTH_IN_MESSAGE:
                message = message.replace(text, str(masked))
        record['@message'] = message
    return len(originals)


def is_sampled(doc_id, percent):
    """Deterministic sampling: the same document always gets the same
    result, so a reprocessed S3 object keeps the same documents."""
    if percent >= 100:
        return True
    if percent <= 0:
        return False
    bucket = int(hashlib.md5(str(doc_id).encode()).hexdigest()[:8], 16) % 100
    return bucket < percent
