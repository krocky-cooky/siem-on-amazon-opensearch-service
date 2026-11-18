# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ALB access log fields 30-36 (D-4) and ALB connection logs (D-5)."""
import pytest

ACCESS_KEY = ('AWSLogs/111122223333/elasticloadbalancing/us-east-1/2026/10/01/'
              '111122223333_elasticloadbalancing_us-east-1_app.my-lb.'
              '0123456789abcdef_20261001T0000Z_192.0.2.1_abcd1234.log.gz')
CONN_KEY = ('AWSLogs/111122223333/elasticloadbalancing/us-east-1/2026/10/01/'
            'conn_log_111122223333_elasticloadbalancing_us-east-1_app.my-lb.'
            '0123456789abcdef_20261001T0000Z_192.0.2.1_abcd1234.log.gz')

BASE = ('https 2026-10-01T00:00:01.000000Z app/my-lb/0123456789abcdef '
        '198.51.100.1:40000 10.0.0.10:80 0.001 0.002 0.000 200 200 100 200 '
        '"GET https://www.example.com:443/path?a=1 HTTP/1.1" "curl/8.0" '
        'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 '
        'arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/tg/1 '
        '"Root=1-abc" "www.example.com" '
        '"arn:aws:acm:us-east-1:1:certificate/x" '
        '0 2026-10-01T00:00:00.990000Z "forward" "-" "-" "10.0.0.10:80" '
        '"200"')
V29 = BASE + ' "-" "-"'
V33 = V29 + ' TID_1234 "new.example.com" "/new" "TransformSuccess"'
V36 = V33 + ' 10.0.0.5 - -'
CONN = ('2026-10-01T00:00:01.514108Z 203.0.113.1 36280 443 TLSv1.2 '
        'ECDHE-RSA-AES128-GCM-SHA256 4.036 '
        '"CN=client.example.com,O=endEntity,C=US" '
        'NotBefore=2026-09-21T22:43:21Z;NotAfter=2027-06-17T22:43:21Z '
        'FEF257372D357EAB Success TID_1234 - app/my-lb/0123 10.0.0.5')
CONN_FAIL = ('2026-10-01T00:00:02.000000Z 203.0.113.2 36281 443 TLSv1.3 '
             'TLS_AES_128_GCM_SHA256 - - - - Failed:ClientCertUntrusted')


def test_logtype_routing(logtype_s3key_dict):
    from siem import utils
    assert utils.get_logtype_from_s3key(
        ACCESS_KEY, logtype_s3key_dict) == 'alb'
    assert utils.get_logtype_from_s3key(
        CONN_KEY, logtype_s3key_dict) == 'alb-connection'


@pytest.mark.parametrize('line', [BASE, V29, V33, V36])
def test_old_and_new_access_logs(parse_text_log, line):
    doc = parse_text_log(line + '\n', 'alb', ACCESS_KEY)[0]['doc']
    assert doc['url']['domain'] == 'www.example.com'
    assert int(doc['http']['response']['status_code']) == 200


def test_new_access_log_fields(parse_text_log):
    doc = parse_text_log(V36 + '\n', 'alb', ACCESS_KEY)[0]['doc']
    assert doc['conn_trace_id'] == 'TID_1234'
    assert doc['transformed_host'] == 'new.example.com'
    assert doc['transformed_uri'] == '/new'
    assert doc['request_transform_status'] == 'TransformSuccess'
    assert doc['ip_address'] == '10.0.0.5'


def test_connection_log(parse_text_log):
    results = parse_text_log(CONN + '\n' + CONN_FAIL + '\n',
                             'alb-connection', CONN_KEY)
    ok, ng = results[0], results[1]
    assert ok['index'].startswith('log-aws-alb-connection-')
    doc = ok['doc']
    assert doc['source']['ip'] == '203.0.113.1'
    assert int(doc['destination']['port']) == 443
    assert doc['event']['outcome'] == 'success'
    assert doc['tls']['version'] == '1.2'
    assert doc['tls']['version_protocol'] == 'tls'
    assert doc['tls']['established'] is True
    assert doc['tls']['client']['subject'].startswith('CN=client')
    assert doc['tls']['client']['not_after'] == '2027-06-17T22:43:21Z'
    assert doc['tls']['client']['x509']['serial_number'] == \
        'FEF257372D357EAB'
    assert doc['conn_trace_id'] == 'TID_1234'

    doc = ng['doc']
    assert doc['event']['outcome'] == 'failure'
    assert doc['event']['reason'] == 'ClientCertUntrusted'
    assert doc['tls']['established'] is False
