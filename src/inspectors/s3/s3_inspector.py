import boto3
from botocore.exceptions import ClientError

#TODO:Create an s3 inspector that can track s3 compliance.

def check_s3_bucket_public_status(bucket_name):

    s3 = boto3.client('s3')

    print(f"Analyzing bucket: {bucket_name}")

    # TODO: Check Encryption
    # TODO: Server Access Logging

    # Check Bucket Policy
    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
        is_policy_public = policy_status.get('PolicyStatus', {}).get('IsPublic', False)

    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            is_policy_public = False
        else:
            print(f"Error checking policy status: {e}")
            is_policy_public = None

    # TODO: Check Public Access
    is_acl_public = False
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})

            if grantee.get('Type') == 'Group' and grantee.get('URI') in [
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://amazonaws.com'
            ]:
                is_acl_public = True
                break

    except ClientError as e:
        print(f"Error checking ACL: {e}")
