# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Helpers for OpenSearch Serverless NextGen collections.

NextGen collections (endpoint ``<id>.aoss.<region>.on.aws``) do not provide
OpenSearch Dashboards (use OpenSearch UI instead) and support data retention
and warm tiering through index settings of time series collections.
"""
import json
import logging

logger = logging.getLogger(__name__)

# limits of index.data.retention in days (NextGen time series only)
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650
# index.warm.after is at least 1 day
MIN_WARM_AFTER_DAYS = 1


def is_nextgen_endpoint(endpoint):
    """True if the endpoint is an OpenSearch Serverless NextGen host."""
    return bool(endpoint) and str(endpoint).endswith('.on.aws')


def _to_days(value, name):
    """Convert a parameter value to int days. Return None if not set."""
    if value is None or str(value).strip() == '':
        return None
    try:
        days = int(str(value).strip())
    except ValueError:
        logger.warning(f'{name} must be a number of days: {value!r}. Ignored')
        return None
    return days


def build_index_settings(retention_days, warm_after_days):
    """Return index settings for NextGen from user parameters (days).

    Invalid values are ignored with a warning, so that a typo never
    blocks the deployment.
    """
    retention = _to_days(retention_days, 'index data retention')
    warm_after = _to_days(warm_after_days, 'index warm after')
    settings = {}
    if retention is not None:
        if MIN_RETENTION_DAYS <= retention <= MAX_RETENTION_DAYS:
            settings['index.data.retention'] = f'{retention}d'
        else:
            logger.warning(
                f'index data retention must be {MIN_RETENTION_DAYS}-'
                f'{MAX_RETENTION_DAYS} days: {retention}. Ignored')
            retention = None
    if warm_after is not None:
        if warm_after < MIN_WARM_AFTER_DAYS:
            logger.warning(
                f'index warm after must be at least {MIN_WARM_AFTER_DAYS} '
                f'day: {warm_after}. Ignored')
        elif retention is not None and warm_after > retention:
            logger.warning(
                f'index warm after ({warm_after}) must not exceed the '
                f'retention ({retention}). Ignored')
        else:
            settings['index.warm.after'] = f'{warm_after}d'
    return settings


def apply_index_settings(index_templates, settings):
    """Add settings to every index template (dict of name -> JSON text).

    Settings already defined in the template are kept. Return the number
    of templates changed.
    """
    if not settings:
        return 0
    changed = 0
    for name, text in list(index_templates.items()):
        template = json.loads(text)
        body = template.setdefault('template', {})
        current = body.setdefault('settings', {})
        before = dict(current)
        for key, value in settings.items():
            current.setdefault(key, value)
        if current != before:
            index_templates[name] = json.dumps(template)
            changed += 1
    return changed
