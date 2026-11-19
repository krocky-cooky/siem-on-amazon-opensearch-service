# OpenSearch UI (optional)

[Back To README](../README.md)

[OpenSearch UI](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/application.html) is an application that is separate from the domain. It lets you use one UI for several data sources. This solution can create an OpenSearch UI application for the managed domain. It is **off by default**, and OpenSearch Dashboards of the domain stays as it is.

This feature was written from the AWS documentation. It was not deployed against a real account, so follow the checks at the end of this page after you enable it.

## What it creates

When `EnableOpenSearchUi` is `true` and `DeploymentTarget` is `opensearch_managed_cluster`:

| Resource | Description |
|---|---|
| `AWS::OpenSearchService::Application` | The application. The SIEM domain is the data source. IAM authentication is used (IAM Identity Center is not configured) |
| `AWS::IAM::ManagedPolicy` | Allows `opensearch:ApplicationAccessAll` and `es:GetApplication` on this application only. It is **not attached** to any user or role |
| Outputs | `OpenSearchUiApplicationId` and `OpenSearchUiAccessPolicyArn` |

OpenSearch Serverless is not supported by this option.

| Parameter | Default | Description |
|---|---|---|
| `EnableOpenSearchUi` | `false` | Create the application |
| `OpenSearchUiName` | `aes-siem-ui` | Name (3-40 characters, lower case letters, digits and `-`) |
| `OpenSearchUiAdminArn` | empty | One IAM user or role ARN that is dashboard administrator. If empty, nobody is administrator. `*` is not accepted |
| `OpenSearchUiAllowedSourceCidrs` | empty | Space-delimited CIDR blocks. If set, the managed policy allows sign-in only from these source IP addresses |

## Who can reach it

By default an OpenSearch UI application has a **public endpoint that accepts requests from any network location**. A request still needs an IAM principal that is allowed `opensearch:ApplicationAccessAll` on the application, so nobody can use the application until you attach the managed policy to a role. But anybody on the internet can reach the login page.

To restrict the network path, use one of these (see [Restricting network access to OpenSearch UI applications](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/application-network-access.html)):

* `OpenSearchUiAllowedSourceCidrs` of this solution, for authenticated requests from known public IP addresses
* A VPC endpoint (`aws:SourceVpce`) condition in the identity-based policy, or a VPC endpoint policy
* A resource control policy that denies `opensearch:ViewLoginPage` and `opensearch:ApplicationAccessAll` outside your network. This is the only option that blocks the login page itself

## Steps after the deployment

1. Attach the managed policy (`OpenSearchUiAccessPolicyArn`) to the IAM roles of the analysts
2. Map the IAM role to a security role of the domain. The application uses the signed-in principal to read the domain, so the role needs access to the SIEM indices. In OpenSearch Dashboards of the domain, open Security > Roles, and add the IAM role ARN as a backend role (mapped user) of a role such as `all_access`, or of your own role with read access to `log-*`. This solution does not do the mapping
3. Open the application. The endpoint is in the output of `aws opensearch get-application --id <OpenSearchUiApplicationId>`. A browser needs a sign-in with the IAM role (for example the AWS console, or a presigned URL as described in [IAM authentication for OpenSearch UI](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/application-auth-iam.html))
4. Import the dashboards: download `saved_objects.zip` from the release assets, then import `dashboard.ndjson` with Dashboards Management > Saved objects > Import in a workspace of the application. This solution does not import them automatically

## Differences to OpenSearch Dashboards of the domain

* The dashboards, the index patterns and the settings of OpenSearch Dashboards of the domain are not copied to the application. Import the saved objects again (step 4)
* Delete or keep OpenSearch Dashboards of the domain as you prefer. This solution keeps writing to it
* Alerts, Security Analytics and the Security plugin screens remain features of the domain. Check which of them you can use in a workspace of the application before you stop using Dashboards of the domain

## Checks to run after you enable it

1. `aws opensearch get-application --id <id>` shows the domain as data source and no IAM Identity Center configuration
2. An anonymous request to `https://<endpoint>/` does not return the application (no HTTP 200 with content)
3. A role without the managed policy gets HTTP 403, and a role with it can sign in
4. The role can query `log-*` of the SIEM domain in the application. If it cannot, check the mapped security role (step 2) and the access policy of the domain. The SIEM sets an access policy that can contain source IP conditions, and requests from the application may not match them
