# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

# Application Load Balancer connection logs (mutual TLS)
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-connection-logs.html


def parse_validity(validity):
    """NotBefore=2023-09-21T22:43:21Z;NotAfter=2026-06-17T22:43:21Z

    >>> parse_validity('NotBefore=a;NotAfter=b')
    {'not_before': 'a', 'not_after': 'b'}
    >>> parse_validity('-')
    {}
    """
    result = {}
    for item in (validity or '').split(';'):
        key, _, value = item.partition('=')
        if key == 'NotBefore' and value:
            result['not_before'] = value
        elif key == 'NotAfter' and value:
            result['not_after'] = value
    return result


def transform(logdata):
    status = logdata.get('tls_verify_status') or '-'
    event = logdata.setdefault('event', {})
    if status == 'Success':
        event['outcome'] = 'success'
    elif status != '-':
        event['outcome'] = 'failure'
        # e.g. Failed:ClientCertUntrusted
        event['reason'] = status.split(':', 1)[-1]

    tls = logdata.setdefault('tls', {})
    protocol = logdata.get('tls_protocol') or '-'
    if protocol != '-':
        # e.g. TLSv1.2, TLSv1.3
        name, _, version = protocol.partition('v')
        tls['version_protocol'] = name.lower()
        if version:
            tls['version'] = version
        tls['established'] = status == 'Success'
    validity = parse_validity(logdata.get('leaf_client_cert_validity'))
    if validity:
        tls.setdefault('client', {}).update(validity)
    if not tls:
        del logdata['tls']
    return logdata
