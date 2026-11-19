# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re
import urllib.parse

# CloudFront standard logging (v2) fields are selectable. Every field used
# here is optional.
RE_CLOUDFRONT_DIST_ID = re.compile(r'(?=[0-9]{0,13}[A-Z])[A-Z0-9]{12,14}')
EMPTY = ('-', '')


def _get(logdata, key):
    value = logdata.get(key)
    if value in EMPTY:
        return None
    return value


def transform(logdata):
    host = _get(logdata, 'x_host_header') or _get(logdata, 'cs_host')
    if host:
        logdata.setdefault('url', {})['domain'] = host
    scheme = _get(logdata, 'cs_protocol')
    path = _get(logdata, 'cs_uri_stem')
    if host and scheme and path:
        query = _get(logdata, 'cs_uri_query')
        full = f'{scheme}://{host}{path}'
        if query:
            full = f'{full}?{query}'
        logdata.setdefault('url', {})['full'] = full

    version = _get(logdata, 'cs_protocol_version')
    if version and '/' in version:
        logdata.setdefault('http', {})['version'] = version.split('/')[1]

    try:
        ua = logdata['user_agent']['original']
        logdata['user_agent']['original'] = urllib.parse.unquote(ua)
    except (KeyError, TypeError):
        pass

    dist_id = _get(logdata, 'distributionid')
    if not dist_id:
        m = RE_CLOUDFRONT_DIST_ID.search(logdata.get('@log_s3key', ''))
        dist_id = m.group(0) if m else 'unknown'
    logdata['distribution_id'] = dist_id

    return logdata
