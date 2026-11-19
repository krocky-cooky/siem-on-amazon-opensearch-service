# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import aws_cdk as cdk
from aws_cdk import aws_iam, aws_opensearchservice


class OpenSearchUi(object):
    """Optional OpenSearch UI application for a managed domain.

    Disabled by default. When enabled, the application uses IAM
    authentication. The endpoint of an OpenSearch UI application is public
    by default, and every request needs an IAM principal that is allowed
    opensearch:ApplicationAccessAll. A managed policy is created for the
    users. It is not attached to anybody. See docs/opensearch_ui.md.
    """

    def __init__(self, scope, PARTITION: str, cfn_parameters_dict: dict,
                 cfn_conditions_dict: dict, aes_domain, aos_domain_arn: str):
        self.scope = scope
        self.PARTITION = PARTITION
        self.enable = cfn_parameters_dict['enable_opensearch_ui']
        self.name = cfn_parameters_dict['opensearch_ui_name']
        self.admin_arn = cfn_parameters_dict['opensearch_ui_admin_arn']
        self.source_cidrs = cfn_parameters_dict['opensearch_ui_source_cidrs']
        self.is_managed_cluster = cfn_conditions_dict['is_managed_cluster']
        self.aes_domain = aes_domain
        self.aos_domain_arn = aos_domain_arn

    def create(self):
        scope = self.scope
        create_ui = cdk.CfnCondition(
            scope, 'CreateOpenSearchUi',
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_equals(self.enable.value_as_string, 'true'),
                self.is_managed_cluster))
        has_admin = cdk.CfnCondition(
            scope, 'HasOpenSearchUiAdmin',
            expression=cdk.Fn.condition_not(cdk.Fn.condition_equals(
                self.admin_arn.value_as_string, '')))
        has_cidrs = cdk.CfnCondition(
            scope, 'HasOpenSearchUiSourceCidrs',
            expression=cdk.Fn.condition_not(cdk.Fn.condition_equals(
                self.source_cidrs.value_as_string, '')))

        app = aws_opensearchservice.CfnApplication(
            scope, 'OpenSearchUiApplication',
            name=self.name.value_as_string,
            data_sources=[
                aws_opensearchservice.CfnApplication.DataSourceProperty(
                    data_source_arn=self.aos_domain_arn,
                    data_source_description=(
                        'SIEM on Amazon OpenSearch Service'))],
            # IAM authentication only: IamIdentityCenterOptions is not set
            app_configs=cdk.Fn.condition_if(
                has_admin.logical_id,
                [{'Key': 'opensearchDashboards.dashboardAdmin.users',
                  'Value': self.admin_arn.value_as_string}],
                cdk.Aws.NO_VALUE),
        )
        app.cfn_options.condition = create_ui
        app.node.add_dependency(self.aes_domain)

        app_arn = (
            f'arn:{self.PARTITION}:opensearch:{cdk.Aws.REGION}:'
            f'{cdk.Aws.ACCOUNT_ID}:application/{app.attr_id}')
        allow_ui = {
            'Effect': 'Allow',
            'Action': 'opensearch:ApplicationAccessAll',
            'Resource': app_arn,
            # restrict the source of authenticated requests, if specified
            'Condition': cdk.Fn.condition_if(
                has_cidrs.logical_id,
                {'IpAddress': {'aws:SourceIp': cdk.Fn.split(
                    ' ', self.source_cidrs.value_as_string)}},
                cdk.Aws.NO_VALUE),
        }
        policy = aws_iam.CfnManagedPolicy(
            scope, 'OpenSearchUiAccessPolicy',
            description=('Allow sign-in to the OpenSearch UI application of '
                         'SIEM on Amazon OpenSearch Service. Attach it to '
                         'the IAM roles of analysts'),
            policy_document={
                'Version': '2012-10-17',
                'Statement': [
                    allow_ui,
                    {'Effect': 'Allow', 'Action': 'es:GetApplication',
                     'Resource': app_arn},
                ]})
        policy.cfn_options.condition = create_ui

        output_id = cdk.CfnOutput(
            scope, 'OpenSearchUiApplicationId',
            description=('ID of the OpenSearch UI application. The endpoint '
                         'is shown by "aws opensearch get-application". It '
                         'is reachable from the internet, and needs an IAM '
                         'principal allowed opensearch:ApplicationAccessAll'),
            value=app.attr_id)
        output_id.condition = create_ui
        output_policy = cdk.CfnOutput(
            scope, 'OpenSearchUiAccessPolicyArn',
            description='Managed policy to attach to the roles of analysts',
            value=policy.ref)
        output_policy.condition = create_ui
        return app
