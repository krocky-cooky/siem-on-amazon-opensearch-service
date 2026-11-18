# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from conftest import load_fixture

from siem import utils

# S3 keys written by siem-log-exporter-eventbridge-events Firehose:
# AWSLogs/<account>/<source>/<detail-type with "_">/<region>/yyyy/MM/dd/
OCSF_KEY = ('AWSLogs/111122223333/aws.securityhub/Findings_Imported_V2/'
            'us-east-1/2026/10/01/siem-eventbridge-events-to-s3-1.gz')
ASFF_KEY = ('AWSLogs/111122223333/aws.securityhub/'
            'Security_Hub_Findings_-_Imported/us-east-1/2026/10/01/'
            'siem-eventbridge-events-to-s3-1.gz')


class TestRouting:
    def test_ocsf_key_goes_to_securityhub_ocsf(self, logtype_s3key_dict):
        assert utils.get_logtype_from_s3key(
            OCSF_KEY, logtype_s3key_dict) == 'securityhub-ocsf'

    def test_asff_key_still_goes_to_securityhub(self, logtype_s3key_dict):
        assert utils.get_logtype_from_s3key(
            ASFF_KEY, logtype_s3key_dict) == 'securityhub'

    def test_asff_logtype_ignores_ocsf_key(self, create_logconfig):
        # safety net if a user.ini changes the section order
        logconfig = create_logconfig('securityhub')
        assert logconfig['s3_key_ignored'].search(OCSF_KEY)
        assert not logconfig['s3_key_ignored'].search(ASFF_KEY)


class TestSecurityHubOcsfEndToEnd:
    def test_findings_imported_v2(self, parse_json_log):
        results = parse_json_log(
            load_fixture('securityhub_ocsf_findings_imported_v2.json'),
            'securityhub-ocsf', OCSF_KEY)
        assert len(results) == 2

        detection, compliance = results
        assert detection['index'] == 'log-ocsf-securityhub-2026-10'
        doc = detection['doc']
        assert doc['@log_type'] == 'securityhub-ocsf-detection-finding'
        assert doc['@timestamp'] == 1790812800000
        assert doc['event']['provider'] == 'guardduty'
        assert doc['event']['kind'] == 'alert'
        assert int(doc['event']['severity']) == 4
        assert doc['rule']['name'].startswith('SSH brute force')
        assert doc['rule']['id'] == 'UnauthorizedAccess:EC2/SSHBruteForce'
        assert doc['source']['ip'] == '198.51.100.10'
        assert int(doc['destination']['port']) == 22
        assert doc['cloud']['account']['id'] == '111122223333'
        # free-form objects are stored as text to avoid mapping conflicts
        assert isinstance(doc['resources'][0]['data'], str)
        assert isinstance(doc['evidences'], str)
        # @id is finding uid. suffix changes when the finding is updated
        assert detection['id'].startswith(
            'arn:aws:guardduty:us-east-1:111122223333:detector/d/finding/'
            'f-0001_')

        doc = compliance['doc']
        assert doc['@log_type'] == 'securityhub-ocsf-compliance-finding'
        assert doc['event']['provider'] == 'security hub'
        assert isinstance(doc['compliance']['control_parameters'], str)
        assert compliance['index'].startswith('log-ocsf-securityhub-')

    def test_same_update_has_same_id(self, parse_json_log):
        raw = load_fixture('securityhub_ocsf_findings_imported_v2.json')
        first = parse_json_log(raw, 'securityhub-ocsf', OCSF_KEY)
        second = parse_json_log(raw, 'securityhub-ocsf', OCSF_KEY)
        assert [r['id'] for r in first] == [r['id'] for r in second]


class TestSecurityHubAsffRegression:
    def test_asff_findings_still_loaded(self, parse_json_log):
        results = parse_json_log(
            load_fixture('securityhub_asff_findings_imported.json'),
            'securityhub', ASFF_KEY)
        assert len(results) == 1
        assert results[0]['index'].startswith('log-aws-securityhub-')
        doc = results[0]['doc']
        assert doc['@log_type'] == 'securityhub'
        assert doc['rule']['id'] == 'security-control/S3.1'
