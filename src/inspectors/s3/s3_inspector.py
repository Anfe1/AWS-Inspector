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
        # Retrieve the bucket policy and checks if the policy is public
        policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
        is_policy_public = policy_status.get('PolicyStatus', {}).get('IsPublic', False)

    # Error handling for policy
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            is_policy_public = False
        else:
            print(f"Error checking policy status: {e}")
            is_policy_public = None

    # Check Bucket ACLs
    is_acl_public = False

    try:
        # Retrieves the bucket ACL, checks grants and grantee groups URI to determine if the ACL is public.
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

    # Check Block Public Access
    bpa_blocks_acls = False
    bpa_blocks_policy = False

    try:
        # Retrieves the bpa configuration for the s3, determines if the public policies are being blocked or restricted
        bpa =  s3.get_public_access_block(Bucket=bucket_name)
        config = bpa.get('PublicAccessBlockConfiguration', {})

        bpa_blocks_acls = config.get('IgnorePublicAcls', False) or config.get('BlockPublicAcls', False)
        bpa_blocks_policy = config.get('RestrictPublicBuckets', False) or config.get('BlockPublicPolicy', False)

    except ClientError as e:

        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlock':
            pass
        else:
            print(f'Error checking BPA: {e}')