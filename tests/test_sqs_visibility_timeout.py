# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SQS visibility timeout and event source mapping settings (#473).

Lambda requires the source queue visibility timeout to be at least the
function timeout and recommends six times the function timeout.
https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-configure.html

The CDK stack is checked with ast and the published CloudFormation
templates with plain text parsing, so neither aws-cdk-lib nor PyYAML is
needed.
"""
import ast
import glob
import os
import re

import pytest

ROOT = os.path.join(os.path.dirname(__file__), '..')
CDK_STACK = os.path.join(ROOT, 'source', 'cdk', 'mysiem', 'aes_siem_stack.py')
TEMPLATES = sorted(
    p for p in glob.glob(os.path.join(
        ROOT, 'deployment', 'siem-on-amazon-opensearch-service*.template'))
    if 'EventSourceMappingForCT2' in open(p).read())

LAMBDA_RECOMMENDED_FACTOR = 6


@pytest.fixture(scope='module')
def cdk_tree():
    with open(CDK_STACK) as f:
        return ast.parse(f.read())


def _constants(tree):
    """Evaluate simple integer constant assignments in the stack."""
    values = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id.isupper()):
            expr = ast.Expression(body=node.value)
            try:
                value = eval(compile(expr, '<ast>', 'eval'),
                             {'__builtins__': {}}, dict(values))
            except Exception:
                continue
            if isinstance(value, int):
                values[node.targets[0].id] = value
    return values


def _calls_with_id(tree, construct_id):
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == construct_id):
            yield node


def _kwarg(call, name):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    raise AssertionError(f'{name} is not set')


def test_cdk_visibility_timeout_is_six_times_lambda_timeout(cdk_tree):
    consts = _constants(cdk_tree)
    assert consts['ES_LOADER_SQS_VISIBILITY_TIMEOUT'] >= (
        consts['ES_LOADER_TIMEOUT'] * LAMBDA_RECOMMENDED_FACTOR)
    # SQS maximum visibility timeout is 12 hours
    assert consts['ES_LOADER_SQS_VISIBILITY_TIMEOUT'] <= 43200

    (queue,) = _calls_with_id(cdk_tree, 'AesSiemSqsSplitLogs')
    duration = _kwarg(queue, 'visibility_timeout')
    assert ast.unparse(duration.args[0]) == (
        'ES_LOADER_SQS_VISIBILITY_TIMEOUT')


def test_cdk_lambda_uses_es_loader_timeout(cdk_tree):
    (func,) = _calls_with_id(cdk_tree, 'LambdaEsLoader')
    duration = _kwarg(func, 'timeout')
    assert ast.unparse(duration.args[0]) == 'ES_LOADER_TIMEOUT'


def test_cdk_security_lake_mapping_batch_size_is_one(cdk_tree):
    (mapping,) = _calls_with_id(cdk_tree, 'EventSourceMappingForCT2')
    assert ast.literal_eval(_kwarg(mapping, 'batch_size')) == 1
    assert ast.literal_eval(
        _kwarg(mapping, 'report_batch_item_failures')) is True


def _resource_block(text, logical_id_prefix):
    match = re.search(
        rf'^  ({re.escape(logical_id_prefix)}[0-9A-F]{{8}}):\n'
        r'((?:    .*\n|\n)+)', text, re.MULTILINE)
    assert match, f'{logical_id_prefix} not found'
    return match.group(2)


def _int_property(block, name):
    match = re.search(rf'^      {name}: (\d+)$', block, re.MULTILINE)
    assert match, f'{name} not found'
    return int(match.group(1))


@pytest.mark.parametrize(
    'template', TEMPLATES, ids=[os.path.basename(p) for p in TEMPLATES])
def test_template_visibility_timeout_and_batch_size(template):
    with open(template) as f:
        text = f.read()
    queue = _resource_block(text, 'AesSiemSqsSplitLogs')
    func = _resource_block(text, 'LambdaEsLoader')
    mapping = _resource_block(text, 'EventSourceMappingForCT2')

    lambda_timeout = _int_property(func, 'Timeout')
    visibility_timeout = _int_property(queue, 'VisibilityTimeout')
    assert visibility_timeout >= lambda_timeout * LAMBDA_RECOMMENDED_FACTOR
    assert _int_property(mapping, 'BatchSize') == 1


def test_templates_found():
    assert len(TEMPLATES) >= 1
