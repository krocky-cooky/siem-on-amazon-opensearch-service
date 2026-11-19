# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

EMPTY = (None, '', '-', 'null')


def split_ip_port(value):
    """'192.0.2.1:80' -> ('192.0.2.1', 80), '[2001:db8::1]:443' too"""
    if value in EMPTY:
        return None, None
    ip, sep, port = str(value).rpartition(':')
    if not sep:
        return value, None
    ip = ip.strip('[]')
    try:
        return ip, int(port)
    except ValueError:
        return ip, None


def _set_endpoint(logdata, key, value):
    ip, port = split_ip_port(value)
    if ip:
        logdata.setdefault(key, {})['ip'] = ip
        if port is not None:
            logdata[key]['port'] = port
        if key == 'source':
            logdata[key]['address'] = ip
    return ip


def transform(logdata):
    src = _set_endpoint(logdata, 'source', logdata.get('sourceIpPort'))
    dst = _set_endpoint(
        logdata, 'destination',
        logdata.get('targetIpPort') or logdata.get('resourceIpPort')
        or logdata.get('destinationIpPort'))
    related = [x for x in (src, dst) if x]
    if related:
        logdata.setdefault('related', {})['ip'] = related

    # arn:aws:vpc-lattice:us-west-2:123456789012:service/svc-1a2b3c4d
    for key in ('serviceArn', 'serviceNetworkArn', 'sourceVpcArn',
                'resourceConfigurationArn'):
        arn = logdata.get(key)
        if arn and arn.count(':') >= 4:
            account = arn.split(':')[4]
            if account:
                logdata.setdefault('cloud', {})['account'] = {'id': account}
                break

    reason = logdata.get('failureReason')
    denied = logdata.get('authDeniedReason')
    if reason in EMPTY and denied not in EMPTY:
        reason = f'AuthDenied:{denied}'
    if reason not in EMPTY:
        logdata['event']['reason'] = reason
    # callerPrincipal / resolvedUser can be Anonymous or Unknown
    user = logdata.get('user', {}).get('id')
    if user in ('Unknown', 'null'):
        del logdata['user']['id']

    code = logdata.get('responseCode')
    if isinstance(code, int) and code >= 400:
        logdata['event']['outcome'] = 'failure'
    elif reason not in EMPTY:
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'success'
    return logdata
