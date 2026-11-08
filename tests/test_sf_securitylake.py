# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json

import pytest

from siem import sf_securitylake


def base(**kwargs):
    logdata = {'time': 1790812800000, 'user': {'name': 'x'}}
    logdata.update(kwargs)
    return logdata


class TestIndexName:
    @pytest.mark.parametrize('logdata, index, log_type', [
        (base(category_name='Findings', category_uid=2),
         'log-ocsf-findings', 'ocsf-findings'),
        (base(category_name='Application Activity', category_uid=6),
         'log-ocsf-application', 'ocsf-application-activity'),
        (base(category_uid=4), 'log-ocsf-network', 'ocsf-network-activity'),
        # OCSF 1.1.0: Application Activity (EKS Audit Logs, #459)
        (base(category_uid=6),
         'log-ocsf-application', 'ocsf-application-activity'),
        # category_uid is empty. derived from class_uid (6003 API Activity)
        (base(category_uid='', class_uid=6003),
         'log-ocsf-application', 'ocsf-application-activity'),
        # no category at all. it used to raise ValueError
        (base(), 'log-ocsf', 'ocsf'),
    ])
    def test_index_name(self, logdata, index, log_type):
        result = sf_securitylake.transform(logdata)
        assert result['__index_name'] == index
        assert result['@log_type'] == log_type


class TestFindingTime:
    def test_ocsf_1_1_finding_info(self):
        logdata = base(category_uid=2, finding_info={
            'created_time': 1790812700000, 'modified_time': 1790812900000})
        result = sf_securitylake.transform(logdata)
        assert result['@timestamp'] == 1790812900000
        assert result['__index_dt'].year == 2026

    def test_ocsf_1_1_created_time_only(self):
        logdata = base(category_uid=2,
                       finding_info={'created_time': '1790812700000'})
        result = sf_securitylake.transform(logdata)
        assert result['@timestamp'] == 1790812700000

    def test_ocsf_1_0_finding_is_still_supported(self):
        logdata = base(category_uid=2,
                       finding={'modified_time': 1790812600000})
        result = sf_securitylake.transform(logdata)
        assert result['@timestamp'] == 1790812600000

    def test_no_finding_time_keeps_timestamp(self):
        logdata = base(category_uid=2)
        result = sf_securitylake.transform(logdata)
        assert '@timestamp' not in result


class TestResourcesData:
    def test_dict_data_is_stringified(self):
        logdata = base(resources=[{'uid': 'r1', 'data': {'a': {'b': 1}}},
                                  {'uid': 'r2', 'data': 'already text'},
                                  {'uid': 'r3'}])
        result = sf_securitylake.transform(logdata)
        assert result['resources'][0]['data'] == '{"a": {"b": 1}}'
        assert result['resources'][1]['data'] == 'already text'
        assert 'data' not in result['resources'][2]


class TestUserName:
    def test_arn_is_shortened(self):
        logdata = base(user={
            'name': 'arn:aws:sts::111122223333:assumed-role/Admin/alice'})
        assert sf_securitylake.transform(logdata)['user']['name'] == 'alice'

    def test_missing_user(self):
        logdata = {'category_uid': 3}
        assert 'user' not in sf_securitylake.transform(logdata)


class TestOcsfApiActivityEndToEnd:
    """EKS audit log style OCSF 1.1.0 API Activity (6003). #459"""
    def test_free_form_api_data_is_stored_as_text(self, parse_json_log):
        event = {
            'category_uid': 6, 'category_name': 'Application Activity',
            'class_uid': 6003, 'class_name': 'API Activity',
            'time': 1790812800000,
            'metadata': {'version': '1.1.0',
                         'product': {'name': 'Amazon EKS'}},
            'api': {'operation': 'create',
                    'request': {'uid': 'r1', 'data': {'kind': 'Pod',
                                                      'spec': {'a': [1]}}},
                    'response': {'data': {'status': {'code': 201}}}},
            'actor': {'user': {'name': 'kubernetes-admin'}},
            'src_endpoint': {'ip': '10.0.0.1'},
            'resources': [{'uid': 'pod-1', 'data': {'ns': 'default'}}],
        }
        results = parse_json_log(
            json.dumps(event), 'ocsf-json', 'ocsf-json/eks/1.json')
        assert len(results) == 1
        assert results[0]['index'] == 'log-ocsf-application-2026-10'
        doc = results[0]['doc']
        assert doc['@log_type'] == 'ocsf-application-activity'
        assert isinstance(doc['api']['request']['data'], str)
        assert isinstance(doc['api']['response']['data'], str)
        assert isinstance(doc['resources'][0]['data'], str)
        assert doc['user']['name'] == 'kubernetes-admin'
        assert doc['source']['ip'] == '10.0.0.1'
