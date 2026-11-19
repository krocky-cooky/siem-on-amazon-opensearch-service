# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    # arn:aws:sts::111122223333:assumed-role/MyRole/session-name
    # arn:aws:iam::111122223333:user/alice
    arn = (logdata.get('identity') or {}).get('arn')
    if arn and 'user' in logdata:
        logdata['user']['name'] = arn.split('/')[-1]

    if logdata.get('errorCode'):
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'success'
    return logdata
