# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""sf_securitylake must not crash when category_uid is missing or empty"""
import doctest

import pytest

from siem import sf_securitylake


def test_doctest():
    assert doctest.testmod(sf_securitylake).failed == 0


@pytest.mark.parametrize('logdata, index, log_type', [
    ({'category_uid': 2}, 'log-ocsf-findings', 'ocsf-findings'),
    ({'category_uid': '', 'class_uid': 4001},
     'log-ocsf-network', 'ocsf-network-activity'),
    ({'class_uid': '3002'}, 'log-ocsf-audit', 'ocsf-audit-activity'),
    ({}, 'log-ocsf', 'ocsf'),
    ({'category_uid': 'abc'}, 'log-ocsf', 'ocsf'),
])
def test_category_without_name(logdata, index, log_type):
    doc = sf_securitylake.transform(dict(logdata))
    assert doc['__index_name'] == index
    assert doc['@log_type'] == log_type
