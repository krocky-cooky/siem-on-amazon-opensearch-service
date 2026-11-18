# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Saved objects for the new Security Hub (C-8)."""
import json
import os

import pytest

SO_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'source', 'saved_objects')
TITLE = 'OCSF Security Hub Findings Summary'


def load(path):
    objs = []
    with open(os.path.join(SO_DIR, path)) as f:
        for line in f:
            line = line.strip()
            if line:
                objs.append(json.loads(line))
    trailer = objs.pop()
    assert trailer['exportedCount'] == len(objs)
    return objs


@pytest.fixture(scope='module')
def bundle():
    return {o['id']: o for o in load('dashboard.ndjson')}


def test_bundle_ids_are_unique():
    objs = load('dashboard.ndjson')
    assert len(objs) == len({o['id'] for o in objs})


def test_each_files_match_bundle(bundle):
    each = (load('each-indexpattern-search/log-ocsf-securityhub.ndjson')
            + load('each-dashboard/ocsf-securityhub.ndjson'))
    for obj in each:
        assert bundle[obj['id']] == obj


def test_dashboard_references_resolve(bundle):
    dash = [o for o in bundle.values()
            if o['type'] == 'dashboard' and o['attributes']['title'] == TITLE]
    assert len(dash) == 1
    for ref in dash[0]['references']:
        vis = bundle[ref['id']]
        index_ref = vis['references'][0]['id']
        assert bundle[index_ref]['attributes']['title'] == \
            'log-ocsf-securityhub-*'


def test_visualized_fields_are_in_index_pattern(bundle):
    pattern = [o for o in bundle.values() if o['type'] == 'index-pattern'
               and o['attributes']['title'] == 'log-ocsf-securityhub-*'][0]
    fields = {f['name'] for f in json.loads(pattern['attributes']['fields'])}
    for obj in load('each-dashboard/ocsf-securityhub.ndjson'):
        if obj['type'] != 'visualization':
            continue
        for agg in json.loads(obj['attributes']['visState'])['aggs']:
            field = agg['params'].get('field')
            if field:
                assert field in fields, f'{field} is not in index pattern'
