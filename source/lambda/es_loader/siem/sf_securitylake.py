# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import json

from siem import utils

# OCSF category_uid => (index suffix, @log_type suffix)
# used only when category_name is not provided
# https://schema.ocsf.io/1.1.0/categories
CATEGORY_UID_MAP = {
    1: ('-system', '-system-activity'),
    2: ('-findings', '-findings'),
    3: ('-audit', '-audit-activity'),
    4: ('-network', '-network-activity'),
    5: ('-config', '-config-inventory'),
    6: ('-application', '-application-activity'),
    7: ('-remediation', '-remediation'),
}

# finding time keys in order of preference.
# OCSF 1.1.0 uses finding_info. OCSF 1.0.0 uses finding
FINDING_TIME_KEYS = (
    'finding_info.modified_time',
    'finding_info.created_time',
    'finding.modified_time',
    'finding.created_time',
)


def to_int(value):
    """convert value to int. return None if it is impossible.

    >>> to_int('2')
    2
    >>> to_int('')

    >>> to_int(None)

    >>> to_int(3.0)
    3
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_category_uid(logdata):
    """return OCSF category_uid.

    category_uid can be empty or missing, so it is derived from class_uid.

    >>> get_category_uid({'category_uid': '2'})
    2
    >>> get_category_uid({'category_uid': '', 'class_uid': 6003})
    6
    >>> get_category_uid({})

    """
    category_uid = to_int(logdata.get('category_uid'))
    if category_uid is None:
        class_uid = to_int(logdata.get('class_uid'))
        if class_uid:
            category_uid = class_uid // 1000
    return category_uid


def get_index_and_logtype_suffix(logdata, category_uid):
    category_name = logdata.get('category_name')
    if category_name:
        index_suffix = f"-{category_name.split()[0].lower()}"
        log_type = f"-{category_name.replace(' ', '-').lower()}"
    else:
        index_suffix, log_type = CATEGORY_UID_MAP.get(category_uid, ('', ''))
    return index_suffix, log_type


def get_finding_time(logdata):
    """return epoch time of finding. OCSF 1.1.0 and 1.0.0 are supported.

    >>> get_finding_time({'finding_info': {'modified_time': 1700000000000}})
    1700000000000
    >>> get_finding_time({'finding': {'created_time': '1700000000000'}})
    1700000000000
    >>> get_finding_time({'finding_info': {'modified_time': ''}})

    """
    for key in FINDING_TIME_KEYS:
        value = to_int(utils.value_from_nesteddict_by_dottedkey(logdata, key))
        if value:
            return value
    return None


def set_finding_timestamp(logdata):
    finding_time = get_finding_time(logdata)
    if finding_time:
        logdata['@timestamp'] = finding_time
        logdata['__index_dt'] = utils.convert_epoch_to_datetime(finding_time)
    return logdata


def stringify_resources_data(logdata):
    """resources[].data is free-form JSON object in OCSF 1.1.0.

    It causes mapping conflict, so convert it to JSON string.
    """
    resources = logdata.get('resources')
    if isinstance(resources, dict):
        resources = [resources]
        logdata['resources'] = resources
    if not isinstance(resources, list):
        return logdata
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        data = resource.get('data')
        if isinstance(data, (dict, list)):
            resource['data'] = json.dumps(data, ensure_ascii=False)
    return logdata


def shorten_user_name(logdata):
    try:
        name = logdata['user']['name']
        if isinstance(name, str) and ':' in name:
            logdata['user']['name'] = name.split(':')[-1].split('/')[-1]
    except (KeyError, TypeError):
        pass
    return logdata


def transform(logdata):
    category_uid = get_category_uid(logdata)
    index_suffix, log_type = get_index_and_logtype_suffix(
        logdata, category_uid)
    logdata['__index_name'] = f'log-ocsf{index_suffix}'
    logdata['@log_type'] = f'ocsf{log_type}'

    if category_uid == 2:
        logdata = set_finding_timestamp(logdata)

    logdata = stringify_resources_data(logdata)
    logdata = shorten_user_name(logdata)

    return logdata
