# Macie Remediation using Security Hub Custom Actions

The CDK project will deploy all AWS resources and infrastructure required to build EC2 forensic modules.

AWS Resources Include:
- (2) AWS Security Hub Custom Actions
- (2) AWS EventBridge rules for Security Hub Custom Actions (status=enabled)
- (2) AWS EventBridge rules for automated remediation (status=disabled)
- (3) AWS Lambda Function & execution IAM role
- (1) AWS KMS key for re-encryption of S3 objects
- OPTIONAL (1) IAM Role to assume

Alternatively, you can deploy this solution using the CloudFormation template [macie-remediation-solution](macie-remediation-solution.yaml). You will need to download the lambda functions into a zip file and add the objects to a new or existing S3 bucket. Once added, you will need to pass the S3 bucket name and object keys (.zip files) in the CloudFormation parameters
- LambdaCodeSourceS3Bucket
- [RemediateS3Bucket](.macie_remediation_cdk/lambdas/remediate_s3_bucket/remediate_s3_bucket.py)
- [RemediateS3Object](./macie_remediation_cdk/lambdas/remediate_s3_object/remediate_s3_object.py)
- [CreateSecHubCustomAction](./macie_remediation_cdk/lambdas/sechub_custom_resource/create_sh_custom_action.py)
- [ResourceProviderFramework](./macie_remediation_cdk/lambdas/resource_provider/resource_provider.zip)

Optional: If deploying for cross-account remediation, you will also need to deploy [macie-remediation-cross-account-iam-role](macie-remediation-cross-account-iam-role.yaml). The only parameter required is the `solutionaccount`, which will be the AWS account where the previous CloudFormation template is deployed. This allows the lambda function to assume the IAM role and take action against the appropriate resources in the AWS account where the finding occurred.

## Prerequisites

AWS Macie must be enabled in the AWS account.
AWS Security Hub must be enabled in the AWS account.

## Build

To build this app, you need to be in the project root folder. Then run the following:

    $ npm install -g aws-cdk
    <installs AWS CDK>

    $ npm install
    <installs appropriate packages found in the package.json>

## Deploy

    $ cdk bootstrap aws://<INSERT_AWS_ACCOUNT>/<INSERT_REGION>
    <build S3 bucket to store files to perform deployment>

    $ cdk deploy MacieRemediationStack
    <deploys the solution resources into the the centralized security account>

    $ cdk deploy MacieRemediationIAMStack --paramters solutionaccount=<INSERT CENTRAL SECURITY AWS ACCOUNT>
    <deploys an optional IAM role if you want to remediate resources cross-account>

## CDK Toolkit

The [`cdk.json`](./cdk.json) file in the root of this repository includes
instructions for the CDK toolkit on how to execute this program.

After building your TypeScript code, you will be able to run the CDK toolkits commands as usual:

    $ cdk ls
    <list all stacks in this program>

    $ cdk synth
    <generates and outputs cloudformation template>

    $ cdk deploy
    <deploys stack to your account>

    $ cdk diff
    <shows diff against deployed stack>

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.