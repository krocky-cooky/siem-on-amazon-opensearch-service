# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    try:
        # event.proto: TCP, UDP, ICMP
        logdata['network']['transport'] = logdata['event']['proto'].lower()
    except KeyError:
        pass

    event_type = logdata['event'].get('event_type')
    if event_type == 'alert':
        logdata['event']['kind'] = 'alert'
        logdata['event']['category'] = 'intrusion_detection'
    elif event_type is None and (
            'tls_error' in logdata['event']
            or 'revocation_check' in logdata['event']):
        # TLS events of the TLS inspection engine have no event_type
        logdata['event']['module'] = 'tls'
        logdata['event']['category'] = 'network'
        logdata['event']['outcome'] = 'failure'
        tls_error = logdata['event'].get('tls_error')
        if tls_error:
            logdata['event']['reason'] = (
                tls_error if isinstance(tls_error, str)
                else str(tls_error))
        else:
            check = logdata['event']['revocation_check']
            logdata['event']['reason'] = (
                f"certificate revocation check: {check.get('status')}")

    return logdata
