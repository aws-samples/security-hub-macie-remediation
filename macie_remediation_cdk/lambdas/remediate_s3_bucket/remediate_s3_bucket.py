import json
import urllib.parse
import os
import boto3
import logging
from botocore.exceptions import ClientError

logger=logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.getenv('AWS_REGION', 'us-east-1')
ROLE_NAME = os.getenv('ROLE_NAME')

sh = boto3.client('securityhub', region_name=REGION)

def s3_assume_role(account):
    """Function to assume role for S3 remediation in target AWS account."""
    sts_client = boto3.client('sts')
    RoleArn = 'arn:aws:iam::{}:role/{}'.format(account, ROLE_NAME)
    logger.info('Assuming Role {} for S3 Bucket remediation...'.format(RoleArn))
    try:
        s3 = sts_client.assume_role(
            RoleArn=RoleArn,
            RoleSessionName='macie-bucket-remediation',
            DurationSeconds=3600,
        )
        s3_target = boto3.client(
        's3',
        aws_access_key_id=s3['Credentials']['AccessKeyId'],
        aws_secret_access_key=s3['Credentials']['SecretAccessKey'],
        aws_session_token=s3['Credentials']['SessionToken'],
        region_name=REGION
        )
    except Exception as exception_handle:
        logger.error('Failed to assume role: {} - {}'.format(RoleArn, str(exception_handle)))
    logger.info('Successfully assumed role: {}'.format(RoleArn))
    return s3_target

def tag_bucket(s3_target, bucket, sh_finding_id):
    logger.info('Tagging {} with finding ID...'.format(bucket))
    tagName = "SH_Finding_ID"
    try:
             response = s3_target.put_bucket_tagging(
                 Bucket = bucket,
                 Tagging={
                     'TagSet': [
                         {
                             'Key': tagName,
                             'Value': str(sh_finding_id)
                         },
                     ]
                 }
             )
             logger.info('Successfully tagged {}.'.format(bucket))
    except ClientError as error_handle:
        logger.error(error_handle.response['Error']['Code'])
        print('Error applying tag {} to {}.'.format(tagName, bucket))
        raise error_handle

def put_public_block(s3_target, bucket):
    logger.info('Applying public access block to {}...'.format(bucket))
    try:
            response = s3_target.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }   
            )
            logger.info('Successfully applied public block to {}.'.format(bucket))
    except ClientError as error_handle:
        logger.error(error_handle.response['Error']['Code'])
        print('Error applying public block {}.'.format(bucket))
        raise error_handle

def put_default_encryption(s3_target, bucket):
    logger.info('Applying default encryption to {}...'.format(bucket))
    try:
        response = s3_target.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms'
                        }
                    },
                ]
            }
        )
        logger.info('Successfully applied default encryption to {}.'.format(bucket))
    except ClientError as error_handle:
        logger.error(error_handle.response['Error']['Code'])
        print('Error applying default encryption to {}.'.format(bucket))
        raise error_handle

def update_sh_finding(sh_finding_id, sh_product_arn):
    logger.info('Updating Security Hub finding {}...'.format(sh_finding_id))
    processed_finding_count = 0
    try:
            response = sh.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': sh_finding_id,
                        'ProductArn': sh_product_arn
                    },
                ],
                Workflow={
                    'Status': 'RESOLVED'
                }
            )
            logger.info("Successfully updated Security Hub finding {}.".format(sh_finding_id))
            processed_finding_count += len(response['ProcessedFindings'])
    except ClientError as error_handle:
        if error_handle.response['Error']['Code'] == 'AccessDeniedException':
            logger.warning('Check permissions to import Security Hub findings.')
        else:
            logger.error(error_handle.response['Error']['Code'])
    if processed_finding_count == 0:
        logger.info("Failed to update {}.".format(response['UnprocessedFindings'][0]))

def lambda_handler(event, context):
#    print("Recevied event: " + json.dumps(event, indent=2))
    bucket = (event['detail']['findings'][0]['Resources'][0]['Id']).split(":::",1)[1] 
    account = event['detail']['findings'][0]['Resources'][0]['Details']['AwsS3Bucket']['OwnerAccountId']
    sh_finding_id = event['detail']['findings'][0]['Id']
    sh_product_arn = event['detail']['findings'][0]['ProductArn']
    s3_target = s3_assume_role(account)
    tag_bucket(s3_target, bucket, sh_finding_id)
    put_public_block(s3_target, bucket)
    put_default_encryption(s3_target, bucket)
    update_sh_finding(sh_finding_id, sh_product_arn)