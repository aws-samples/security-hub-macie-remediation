# Test Event
# {
#     "ResourceProperties": {
#         "Name": "Remediate with SHARR",
#         "Description": "Submit the finding to AWS Security Hub Automated Response and Remediation",
#         "Id": "SHARRRemediation"
#     },
#     "RequestType": "create",
#     "ResponseURL": "https://bogus"
# }
import os
import json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import logging
from botocore.vendored import requests
from urllib.request import Request

# initialize logger
logger=logging.getLogger()
logger.setLevel(logging.INFO)
REGION = os.getenv('AWS_REGION', 'us-east-1')
PARTITION = os.getenv('AWS_PARTITION', default='aws') # Set by deployment template

securityhub = boto3.client('securityhub')

BOTO_CONFIG = Config(
    retries ={
        'mode': 'standard'
    }
)

class CustomAction(object):
    """
    Security Hub CustomAction class
    """
    name = ''
    description = ''
    id = ''
    account = ''

    def __init__(self, account, properties):
        self.name = properties.get('Name', '')
        self.description = properties.get('Description', '')
        self.id = properties.get('Id', '')
        self.account = account
    
    def create(self):
        try:
            return securityhub.create_action_target(
                Name=self.name,
                Description=self.description,
                Id=self.id
            )['ActionTargetArn']
        except ClientError as error:
            if error.response['Error']['Code'] == 'ResourceConflictException':
                logger.info('ResourceConflictException: already exists. Continuing')
                return
            elif error.response['Error']['Code'] == 'InvalidAccessException':
                logger.info('InvalidAccessException - Account is not subscribed to AWS Security Hub.')
                return 'FAILED'
            else:
                logger.error(error)
                return 'FAILED'
        except Exception as e:
            return 'FAILED'

    def delete(self):
        try:
            target_arn = f'arn:{PARTITION}:securityhub:{REGION}:{self.account}:action/custom/{self.id}'
            logger.info(target_arn)
            securityhub.delete_action_target(ActionTargetArn=target_arn)
            return 'SUCCESS'
        except ClientError as error:
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info('ResourceNotFoundException - nothing to delete.')
                return 'SUCCESS'
            elif error.response['Error']['Code'] == 'InvalidAccessException':
                logger.info('InvalidAccessException - not subscribed to Security Hub (nothing to delete).')
                return 'SUCCESS'
            else:
                logger.error(error)
                return 'FAILED'
        except Exception as e:
            logger.error(e)
            return 'FAILED'

class CfnResponse(object):
    response_body = {}
    response_url = ''
    response_headers = {}

    def __init__(self, event, context, response_status, response_data, physical_resource_id, reason=None):
        self.response_url = event['ResponseURL']
       
        message = 'See details in CloudWatch Log Stream: ' + context.log_stream_name
        if reason:
            message = str(reason)[0:255] + '... ' + message

        raw_response_body = {
            'Status': response_status,
            'PhysicalResourceId': physical_resource_id or context.log_stream_name,
            'Reason': message,
            'StackId': event['StackId'],
            'RequestId': event['RequestId'],
            'LogicalResourceId': event['LogicalResourceId']
        }
        if response_data and isinstance(response_data, dict):
            raw_response_body['Data'] = response_data
        
        self.response_body = json.dumps(raw_response_body)

        self.response_headers = {
            'content-type': '',
            'content-length': str(len(self.response_body))
        }

    def send(self):
        try:
            if self.response_url == 'http://pre-signed-S3-url-for-response':
                logger.info("CloudFormation returned status code: THIS IS A TEST OUTSIDE OF CLOUDFORMATION")
            else:
                response = requests.put(self.response_url,
                                        data=self.response_body,
                                        headers=self.response_headers)
                logger.info("CloudFormation returned status code: " + response.reason)
        except Exception as e:
            logger.error("send(..) failed executing requests.put(..): " + str(e))
            raise

def lambda_handler(event, context):
    response_data = {}
    physical_resource_id = ''
    err_msg = ''

    properties = event.get('ResourceProperties', {})
    logger.info(json.dumps(properties)) 
    account_id = boto3.client('sts').get_caller_identity()['Account']
    customAction = CustomAction(account_id, properties)
    physical_resource_id = 'CustomAction' + properties.get('Id', 'ERROR')

    try:
        status = 'ERROR'
        if event['RequestType'].upper() == 'CREATE' or event['RequestType'].upper() == 'UPDATE':
            logger.info(event['RequestType'].upper() + ': ' + physical_resource_id)
            custom_action_result = customAction.create()
            if custom_action_result == 'FAILED':
                status = 'FAILED'
            else:
                response_data['Arn'] = custom_action_result
                status = 'SUCCESS' 

        elif event['RequestType'].upper() == 'DELETE':
            logger.info('DELETE: ' + physical_resource_id)
            status = customAction.delete()

        else:
            err_msg = 'Invalid RequestType: ' + event['RequestType']
            logger.error(err_msg)

        cloudformation = CfnResponse(
            event,
            context,
            status,
            response_data,
            physical_resource_id,
            err_msg
        )
        cloudformation.send()
        return

    except Exception as err:
        logger.error('An exception occurred: ')
        err_msg = err.__class__.__name__ + ': ' + str(err)
        logger.error(err_msg)