# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    status = str(logdata.get('status', '')).lower()
    if status == 'success':
        logdata['event']['outcome'] = 'success'
    elif status in ('failure', 'failed'):
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'unknown'

    ips = [x for x in (logdata.get('source', {}).get('ip'),
                       logdata.get('destination', {}).get('ip')) if x]
    if ips:
        logdata.setdefault('related', {})['ip'] = ips
    if logdata.get('source', {}).get('ip'):
        logdata['source']['address'] = logdata['source']['ip']
    users = [x for x in (logdata.get('user', {}).get('id'),
                         logdata.get('user', {}).get('name'),
                         logdata.get('user', {}).get('email')) if x]
    if users:
        logdata.setdefault('related', {})['user'] = list(dict.fromkeys(users))
    return logdata
