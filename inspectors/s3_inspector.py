import boto3

#TODO:Create an s3 inspector that can track s3 compliance.

s3 = boto3.client('s3')
buckets = s3.list_buckets().get('Buckets', [])

for bucket in buckets:

    name = bucket['Name']
    #TODO: Check Public Access
    #TODO: Check Encryption
    #TODO: Server Access Logging

