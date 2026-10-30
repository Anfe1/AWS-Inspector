import boto3
from botocore.exceptions import ClientError

#TODO:Create an s3 inspector that can track s3 compliance.

def check_s3_bucket_public_status(bucket_name):
    return None

s3 = boto3.client('s3')
buckets = s3.list_buckets().get('Buckets', [])

for bucket in buckets:

    name = bucket['Name']
    #TODO: Check Public Access
    #TODO: Check Encryption
    #TODO: Server Access Logging

