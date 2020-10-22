# Creating a Lambda function that evaluates IAM key age and sending an SES notification if key is older than X days
# Author Marshawn A. McLeod, Cloud Infrastructure Architect 
import boto3
from datetime import datetime, timedelta
import dateutil.parser

MAX_KEY_AGE = 90
MY_EMAIL = "" 

iam_client = boto3.client('iam')
ses_client = boto3.client('ses')

def list_access_keys(username_list): # ['User1', 'User2']
    access_keys = []
    for user in username_list:
        response = iam_client.list_access_keys(
            UserName=user
        )
        access_keys.append(response) 
    return access_keys # ['User1': ['Key1': {'CreateDate': '01/01/2000'}, 'Key2': {'CreateDate': '01/01/2000'}], 'User2': ['Key1': {'CreateDate': '01/01/2000'}]

def get_username_list():
    username_list = []
    response = iam_client.list_users()
    for user in response['Users']:
        username_list.append(user['UserName'])
    return username_list        # ['User1', 'User2']

def evaluate_key_age(access_key_list): # ['User1': ['Key1': {'CreateDate': '01/01/2000'}, 'Key2': {'CreateDate': '01/01/2000'}], 'User2': ['Key1': {'CreateDate': '01/01/2000'}]
    today = datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())
    # Looping through keys
    for u in access_key_list:
        for k in u['AccessKeyMetadata']:
            create_date = k['CreateDate']
            time_delta = today - create_date
            key_age = time_delta.days
            if key_age > MAX_KEY_AGE:
                print ("Key " + k['AccessKeyId'] + " for user " + k['UserName'] + " has exceeded 90 days! It is currently at: " + str(key_age))
                email_text = "Key " + k['AccessKeyId'] + " for user " + k['UserName'] + " has exceeded 90 days! It is currently at: " + str(key_age)
                # Get user tags
                response = get_user(Username=k['UserName'])
                for t in response:
                    if t['Name'] == "email_address":
                        email_address = t['Value']
                send_email (email_text, email_address)

            else:
                print ("Key is not old")
            #print (key_age)
        
def send_email (text, email_address=MY_EMAIL):
    response = ses_client.send_email(
        Source=email_address,
        Destination={
            'ToAddresses': [
                email_address
            ]
        },
        Message={
            'Subject': {
                'Data': 'IAM Key Violation'
            },
            'Body': {
                'Text': {
                    'Data': text
                }
            }
        }
    )
def lambda_handler(event, context):
    username_list = get_username_list()
    access_key_list = list_access_keys(username_list)
    evaluate_key_age(access_key_list)