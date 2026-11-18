# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

# Transform OCSF findings of new AWS Security Hub.
#
# New Security Hub sends findings in OCSF to EventBridge with detail-type
# "Findings Imported V2". Security Hub CSPM keeps ASFF and is handled by
# sf_securityhub.py.
#
# Findings are stored in log-ocsf-securityhub-* so that the OCSF index
# template (log-ocsf-*) is applied. It is separated from log-ocsf-findings-*
# of Security Lake to avoid duplication when both are enabled.

import hashlib

from siem import sf_securitylake

INDEX_NAME = 'log-ocsf-securityhub'

# https://schema.ocsf.io/1.1.0/classes/vulnerability_finding etc.
CLASS_UID_LOG_TYPE = {
    2001: 'security-finding',
    2002: 'vulnerability-finding',
    2003: 'compliance-finding',
    2004: 'detection-finding',
    2005: 'incident-finding',
    2006: 'data-security-finding',
}


def get_finding_uid(logdata):
    finding_uid = (logdata.get('finding_info') or {}).get('uid')
    if not finding_uid:
        finding_uid = (logdata.get('metadata') or {}).get('uid')
    return finding_uid


def transform(logdata):
    class_uid = sf_securitylake.to_int(logdata.get('class_uid'))
    log_type = CLASS_UID_LOG_TYPE.get(class_uid, 'findings')
    logdata['__index_name'] = INDEX_NAME
    logdata['@log_type'] = f'securityhub-ocsf-{log_type}'

    # event.provider: product which generated the finding. eg) GuardDuty
    product_name = (
        ((logdata.get('metadata') or {}).get('product') or {}).get('name'))
    if product_name:
        if not isinstance(logdata.get('event'), dict):
            logdata['event'] = {}
        logdata['event']['provider'] = product_name.lower()

    logdata = sf_securitylake.set_finding_timestamp(logdata)

    # same finding is updated many times. keep each update as new document
    # and make it idempotent when the same update is delivered again.
    finding_uid = get_finding_uid(logdata)
    if finding_uid:
        logdata['@id'] = finding_uid
        status = logdata.get('status') or logdata.get('status_id') or ''
        modified_time = sf_securitylake.get_finding_time(logdata) or ''
        logdata['__doc_id_suffix'] = hashlib.md5(
            f"{modified_time}{status}".encode()).hexdigest()
        # confirmd and ignored Rule-143469

    logdata = sf_securitylake.stringify_resources_data(logdata)
    logdata = sf_securitylake.shorten_user_name(logdata)

    return logdata
