import { CustomResource, Stack, StackProps, Duration, Fn, RemovalPolicy } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as customresources from 'aws-cdk-lib/custom-resources';
import { Rule } from 'aws-cdk-lib/aws-events';
import { LambdaFunction } from 'aws-cdk-lib/aws-events-targets';
import { Function, Runtime, Code } from 'aws-cdk-lib/aws-lambda';
import { join } from 'path';
import { Key } from 'aws-cdk-lib/aws-kms';

export class MacieRemediationStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // CDK Custom Resource to create Security Hub Custom Action
    const CustomResourceLambdaRole = new iam.Role(this, 'CustomResourceLambdaRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "CustomResourceLambdaRole",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'CustomResourceLambdaRoleExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });

    const CreateSecHubCustomAction = new Function(this, 'CreateSecHubCustomAction', {
      functionName: "CreateSecHubCustomAction",
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/sechub_custom_resource/")),
      handler: 'create_sh_custom_action.lambda_handler',
      description: 'Create AWS Security Hub Custom Action.',
      timeout: Duration.seconds(300),
      role: CustomResourceLambdaRole,
      reservedConcurrentExecutions: 100,
      environment: {
      },
    });

    const lambdaCustomActionPolicyDoc = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "CreateSecurityHubCustomAction",
          effect: iam.Effect.ALLOW,
          actions: [
            "securityhub:DescribeActionTarget",
            "securityhub:UpdateActionTarget",
            "securityhub:CreateActionTarget"
          ],
          resources: [
            '*'
          ]   
        }),
      ],
    });

    const CustomResourceLambdaManagedPolicy = new iam.ManagedPolicy(this, 'CustomResourceLambdaManagedPolicy', {
      description: 'Policy for automation to deploy Security Hub Custom Action.',
      document:lambdaCustomActionPolicyDoc,
      managedPolicyName: 'CustomResourceLambdaManagedPolicy',
      roles: [CustomResourceLambdaRole]
    });
    
    const provider = new customresources.Provider(this, 'ResourceProvider', {
      onEventHandler: CreateSecHubCustomAction,
    });

    const macie_policy_custom_action_id = "MacieS3BucketPolicy"
    const macie_policy_custom_action = new CustomResource(this, 'macie_policy_custom_action', {
      serviceToken: provider.serviceToken,
      resourceType: 'Custom::ActionTarget',
      properties: {
          Name: "Macie Policy Finding",
          Description: 'Custom Action for Macie Policy Findings.',
          Id: macie_policy_custom_action_id,
          Account: this.account,
          Partition: this.partition
      }
    });

    const macie_sensitive_data_custom_action_id = "MacieSensitiveData"
    const macie_sensitive_data_custom_action = new CustomResource(this, 'macie_sensitive_data_custom_action', {
      serviceToken: provider.serviceToken,
      resourceType: 'Custom::ActionTarget',
      properties: {
          Name: "Macie Data Finding",
          Description: 'Custom Action for Macie Data Findings.',
          Id: macie_sensitive_data_custom_action_id,
          Account: this.account,
          Partition: this.partition
      }
    });

    // Remediate S3 Bucket Lambda Function Resources
    const remediate_s3_bucket_role_name = 'Macie_S3_Bucket_Remediation'
    const remediate_s3_bucket_role = new iam.Role(this, 'remediate_s3_bucket_role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: remediate_s3_bucket_role_name,
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaRemediateS3BucketPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });
    
    const RemediateS3Bucket = new Function(this, 'RemediateS3Bucket', {
      functionName: "Remediate_Macie_S3_Bucket",
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/remediate_s3_bucket/")),
      handler: 'remediate_s3_bucket.lambda_handler',
      description: 'Remediate S3 Bucket from a Macie finding.',
      timeout: Duration.seconds(300),
      role: remediate_s3_bucket_role,
      reservedConcurrentExecutions: 100,
      environment: {
        ROLE_NAME: remediate_s3_bucket_role.roleName
      },
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
        }),
        new iam.PolicyStatement({
          sid: "IAMAssumerole",
          effect: iam.Effect.ALLOW,
          actions: [
            "sts:AssumeRole"
          ],
          resources: [
            "*"
          ],
            conditions: {
              StringLike:{
                "aws:PrincipalArn": Fn.join('', ['arn:aws:iam::*:role/', remediate_s3_bucket_role_name])
              }
            }
        }),
      ],
    });

    const lambdaRemediateS3BucketManagedPolicy = new iam.ManagedPolicy(this, 'lambdaRemediateS3BucketManagedPolicy', {
      description: '',
      document:lambdaRemediateS3BucketPolicyDocument,
      managedPolicyName: 'lambdaRemediateS3BucketManagedPolicy',
      roles: [remediate_s3_bucket_role]
    });

    const RemediateS3Bucket_target = new LambdaFunction(RemediateS3Bucket)

    // Remediate S3 Object Lambda Function Resources
    // KMS Key for S3 Object resources
    const macie_kms_key = new Key(this, 'macie_kms_key', {
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description: 'KMS key to reencrypt objects.',
      enableKeyRotation: true,
      alias: 'macie_key'
    });

    const remediate_s3_object_role_name = 'Macie_S3_Object_Remediation'
    const remediate_s3_object_role = new iam.Role(this, 'remediate_s3_object_role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: remediate_s3_object_role_name,
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaRemediateS3ObjectPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });
    
    macie_kms_key.grantEncryptDecrypt(remediate_s3_object_role)
    macie_kms_key.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ],
        principals: [remediate_s3_object_role],
        resources: ['*'],
        conditions: {
          Bool:{
            "kms:GrantIsForAWSResource": true
          }
        }
      })
    );

    const RemediateS3Object = new Function(this, 'RemediateS3Object', {
      functionName: "Remediate_Macie_S3_Object",
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/remediate_s3_object/")),
      handler: 'remediate_s3_object.lambda_handler',
      description: 'Remediate S3 Object from a Macie finding.',
      timeout: Duration.seconds(300),
      role: remediate_s3_object_role,
      reservedConcurrentExecutions: 100,
      environment: {
        KMS_KEY: macie_kms_key.keyArn,
        ROLE_NAME: remediate_s3_object_role.roleName
      },
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
          sid: "IAMAssumerole",
          effect: iam.Effect.ALLOW,
          actions: [
            "sts:AssumeRole"
          ],
          resources: [
            "*"
          ],
            conditions: {
              StringLike:{
                "aws:PrincipalArn": Fn.join('', ['arn:aws:iam::*:role/', remediate_s3_object_role_name])
              }
            }
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

    const RemediateS3Object_target = new LambdaFunction(RemediateS3Object)


    // CloudWatch Automated EventBridge rule for Macie findings
    const Automated_Respond_Macie_Data_finding = new Rule(this, 'Automated_Respond_Macie_Data_finding', {
      description: 'Automatically responds to a Macie S3 Sensitive Data finding in Security Hub.',
      enabled: false,
      eventPattern: {
        "source": [
          "aws.securityhub"
        ],
        "detailType": [
          "Security Hub Findings - Imported"
        ],
        "detail": {
          "findings": {
            "ProductName":[
              "Macie"
            ],
            "Types":[
              { "prefix": "Sensitive Data Identifications/PII/SensitiveData:"}
            ],
            "WorkflowState": [
              "NEW"
            ],
            "RecordState": [
              "ACTIVE"
            ],
          }
        }
      },
      ruleName: 'Autoremediate_Macie_Sensitive_Data_Finding',
      targets: [RemediateS3Object_target]
    }
    );

      // CloudWatch EventBridge rule for Macie findings
      const Automated_Respond_Macie_Policy_finding = new Rule(this, 'Automated_Respond_Macie_Policy_finding', {
        description: 'Automatically responds to a Macie S3 Bucket Policy finding in Security Hub.',
        enabled: false,
        eventPattern: {
          "source": [
            "aws.securityhub"
          ],
          "detailType": [
            "Security Hub Findings - Imported"
          ],
          "detail": {
            "findings": {
              "ProductName":[
                "Macie"
              ],
              "Types":[
                { "prefix": "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-S3"}
              ],
              "WorkflowState": [
                "NEW"
              ],
              "RecordState": [
                "ACTIVE"
              ],
            }
          }
        },
        ruleName: 'Autoremediate_Macie_Policy_Finding',
        targets: [RemediateS3Bucket_target]
      }
      );
    // CloudWatch Automated EventBridge rule for Macie findings
    const Custom_Action_Respond_Macie_Data_finding = new Rule(this, 'Custom_Action_Respond_Macie_Data_finding', {
      description: 'Invoked from Custom Action to respond to a Macie S3 Sensitive Data finding in Security Hub.',
      enabled: true,
      eventPattern: {
        "source": [
          "aws.securityhub"
        ],
        "detailType": [
          "Security Hub Findings - Custom Action"
        ],
        "resources": [
          Fn.join('', ["arn:aws:securityhub:", this.region, ":", this.account, ":action/custom/", macie_sensitive_data_custom_action_id]),
        //  macie_sensitive_data_custom_action.getAttString('PhysicalResourceId')
        ]
      },
      ruleName: 'Custom_Action_Macie_Sensitive_Data_Finding',
      targets: [RemediateS3Object_target]
    }
    );

      // CloudWatch Custom Action EventBridge rule for Macie findings
      const Custom_Action_Respond_Macie_Policy_finding = new Rule(this, 'Custom_Action_Respond_Macie_Policy_finding', {
        description: 'Invoked from Custom Action to respond to a Macie S3 Bucket Policy finding in Security Hub.',
        enabled: true,
        eventPattern: {
          "source": [
            "aws.securityhub"
          ],
          "detailType": [
            "Security Hub Findings - Custom Action"
          ],
          "resources": [
            Fn.join('', ["arn:aws:securityhub:", this.region, ":", this.account, ":action/custom/", macie_policy_custom_action_id]),
          //  macie_policy_custom_action.getAttString('PhysicalResourceId')
          ]
        },
        ruleName: 'Custom_Action_Macie_Policy_Finding',
        targets: [RemediateS3Bucket_target]
      }
      );
     
  }
}
