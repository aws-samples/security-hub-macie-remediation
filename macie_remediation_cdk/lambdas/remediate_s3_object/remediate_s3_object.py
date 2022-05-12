import json
import urllib.parse
import os
import boto3
import logging
from botocore.exceptions import ClientError

logger=logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.getenv('AWS_REGION', 'us-east-1')
KMS_KEY = os.getenv('KMS_KEY')
ROLE_NAME = os.getenv('ROLE_NAME')

def s3_assume_role(account):
    """Function to assume role for S3 remediation in target AWS account."""
    sts_client = boto3.client('sts')
    RoleArn = 'arn:aws:iam::{}:role/{}'.format(account, ROLE_NAME)
    logger.info('Assuming Role {} for S3 remediation...'.format(RoleArn))
    try:
        s3 = sts_client.assume_role(
            RoleArn=RoleArn,
            RoleSessionName='macie-object-remediation',
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

sh = boto3.client('securityhub', region_name=REGION)

def tag_object(s3_target, bucket, sh_finding_id, key):
    logger.info('Tagging {} with finding ID...'.format(key))
    tagName = "SH_Finding_ID"
    try:
             response = s3_target.put_object_tagging(
                 Bucket = bucket,
                 Key = key,
                 Tagging={
                     'TagSet': [
                         {
                             'Key': tagName,
                             'Value': str(sh_finding_id)
                         },
                     ]
                 }
             )
             logger.info('Successfully tagged {} in {}.'.format(key, bucket))
    except ClientError as error_handle:
        logger.error(error_handle.response['Error']['Code'])
        print('Error applying tag {} to {}.'.format(tagName, key))
        raise error_handle

def reencrypt_object(s3_target,bucket, key):
    logger.info('Attempting encryption of {} in {} using {}...'.format(key, bucket, KMS_KEY))
    try:
        response = s3_target.copy_object(
            CopySource={
                "Bucket": bucket,
                "Key": key
            },
            Bucket=bucket,
            Key=key,
            SSEKMSKeyId=KMS_KEY,
            ServerSideEncryption='aws:kms'
        )
        logger.info('Successfully encrypted {} in {} using {}...'.format(key, bucket, KMS_KEY))
    except ClientError as error_handle:
        logger.error(error_handle.response['Error']['Code'])
        print('Error encryption of {} with {}.'.format(key, KMS_KEY))
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
    bucket = str((event['detail']['findings'][0]['Resources'][0]['Id']).split(":::",1)[1])
    account = event['detail']['findings'][0]['Resources'][0]['Details']['AwsS3Bucket']['OwnerAccountId']
    key = (str((event['detail']['findings'][0]['Resources'][1]['Id']).split((bucket + '/'),1)[1]))
    sh_finding_id = event['detail']['findings'][0]['Id']
    sh_product_arn = event['detail']['findings'][0]['ProductArn']
    s3_target = s3_assume_role(account)
    tag_object(s3_target, bucket, sh_finding_id, key)
    reencrypt_object(s3_target, bucket, key)
    update_sh_finding(sh_finding_id, sh_product_arn)