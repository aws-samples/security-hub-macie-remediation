import os
import json
import boto3
import logging
from botocore.exceptions import ClientError
from urllib.request import Request

logger=logging.getLogger()
logger.setLevel(logging.INFO)
REGION = os.getenv('AWS_REGION')
PARTITION = os.getenv('AWS_PARTITION')

sh = boto3.client('securityhub', region_name=REGION)

def lambda_handler(event, context):
    print(event)
    request_type = event['RequestType'].lower()
    if request_type == 'create':
        return on_create(event)
    if request_type == 'update':
        return on_create(event)
    if request_type == 'delete':
        return on_delete(event)
    raise Exception(f'Invalid request type: {request_type}')


def on_create(event):
    props = event["ResourceProperties"]
    custom_action_arn = create_custom_action(props)
    physical_id = custom_action_arn
    return {'PhysicalResourceId': physical_id}

def on_delete(event):
    props = event["ResourceProperties"]
    target_arn = 'arn:' + props['Partition'] + ':securityhub:'+ REGION + ':' + props['Account'] + ':action/custom/' + props['Id']

    try:
        sh.delete_action_target(
            ActionTargetArn=target_arn
        )
    except ClientError as error_handle:
        logger.error(error_handle.response['Error']['Code'])

    
def create_custom_action(props):
    try:
        response = sh.create_action_target(
                Name = props['Name'],
                Description = props['Description'],
                Id = props['Id']
            )['ActionTargetArn']
    except ClientError as error_handle:
        if error_handle.response['Error']['Code'] == 'ResourceConflictException':
            logger.info('Custom Action already exists!')
            return
        else:
            logger.error(error_handle.response['Error']['Code'])
    return response