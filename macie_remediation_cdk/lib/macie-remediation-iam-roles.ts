import { Stack, StackProps, Fn, CfnParameter } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';

export class MacieRemediationIAMStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const solution_account = new CfnParameter(this, 'solution_account', {
      type: 'String',
      description: 'AWS Account Macie remediation solution was deployed in.'
    })

    // Remediate S3 Bucket Lambda Function Resources
    const remediate_s3_bucket_role_name = 'Macie_S3_Bucket_Remediation'
    const remediate_s3_bucket_role = new iam.Role(this, 'remediate_s3_bucket_role', {
      assumedBy: new iam.ArnPrincipal(
        Fn.join('', ['arn:aws:iam::', solution_account.valueAsString ,':role/', remediate_s3_bucket_role_name])
        ),      roleName: remediate_s3_bucket_role_name,
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaRemediateS3BucketPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });
  
    const lambdaRemediateS3BucketPolicyDocument = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "KMSUse",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:Encrypt",
            "kms:GenerateDataKey*",
            "kms:DescribeKey",
            "kms:Decrypt"
          ],
          resources: [
            "*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "S3RemediateBucket",
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:PutBucketTagging",
            "s3:PutBucketPublicAccessBlock",
            "s3:PutEncryptionConfiguration"
          ],
          resources: [
            "*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SecurityHubUpdate",
          effect: iam.Effect.ALLOW,
          actions: [
            "securityhub:BatchUpdateFindings"
          ],
          resources: [
            "*"
          ]   
        })
      ],
    });

    const lambdaRemediateS3BucketManagedPolicy = new iam.ManagedPolicy(this, 'lambdaRemediateS3BucketManagedPolicy', {
      description: '',
      document:lambdaRemediateS3BucketPolicyDocument,
      managedPolicyName: 'lambdaRemediateS3BucketManagedPolicy',
      roles: [remediate_s3_bucket_role]
    });

    const remediate_s3_object_role_name = 'Macie_S3_Object_Remediation'
    const remediate_s3_object_role = new iam.Role(this, 'remediate_s3_object_role', {
      assumedBy: new iam.ArnPrincipal(
        Fn.join('', ['arn:aws:iam::', solution_account.valueAsString ,':role/', remediate_s3_object_role_name])
        ),
      roleName: remediate_s3_object_role_name,
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaRemediateS3ObjectPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });

    const lambdaRemediateS3ObjectPolicyDocument = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "kmsAllowAccess",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:Encrypt",
            "kms:GenerateDataKey*",
            "kms:DescribeKey",
            "kms:Decrypt"
          ],
          resources: [
            "*"
          ]
        }),
        new iam.PolicyStatement({
          sid: "S3RemediateObject",
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:PutObjectTagging",
            "s3:PutObject"
          ],
          resources: [
            "*"
          ]
        }),
        new iam.PolicyStatement({
          sid: "SecurityHubUpdate",
          effect: iam.Effect.ALLOW,
          actions: [
            "securityhub:BatchUpdateFindings"
          ],
          resources: [
            "*"
          ]   
        }),
      ],
    });

    const lambdaRemediateS3ObjectManagedPolicy = new iam.ManagedPolicy(this, 'lambdaRemediateS3ObjectManagedPolicy', {
      description: '',
      document:lambdaRemediateS3ObjectPolicyDocument,
      managedPolicyName: 'lambdaRemediateS3ObjectManagedPolicy',
      roles: [remediate_s3_object_role]
    });

  }
}
