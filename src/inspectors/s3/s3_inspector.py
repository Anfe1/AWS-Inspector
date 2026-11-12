import boto3
from botocore.exceptions import ClientError

#TODO:Create an s3 inspector that can track s3 compliance.
#TODO: Add more comments
#TODO: Finish logging system

def check_s3_bucket_public_status(bucket_name):

    # Initialize s3 client
    s3 = boto3.client('s3')

    print(f"Analyzing bucket: {bucket_name}")

    # Check Bucket Policy
    print("|---------Initiating Bucket Policy Check---------|")
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
        print("|---------Initiating Bucket ACL Check---------|")
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
        print("|---------Initiating BPA configuration Check---------|")
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


    # Check Encryption configuration
    try:
        print("|---------Initiating Bucket Encryption Check---------|")
        # Retrieves the bucket encryption configuration and checks if any of the encryption settings are enabled.

        encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = encryption['ServerSideEncryptionConfiguration']['Rules']

        for rule in rules:
            algorithm = rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']

            if 'KMSMasterKeyId' in rule['ApplyServerSideEncryptionByDefault']:
                kms_key = rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyId']
            else:
                kms_key = None

    except ClientError as e:

        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            print("No explicit default encryption configuration found. S3 falls back to automatic SSE-S3.")
        else:
            print(f"An error occurred: {e}")

    # Check Bucket Logging
    try:
        print("|---------Initiating Bucket Logging Check---------|")
        # Check if logging is enabled and extracts loggin info
        logging_status =  s3.get_bucket_logging(Bucket=bucket_name)

        if 'LoggingEnabled' in logging_status:
            logging_info = logging_status['LoggingEnabled']
            target_bucket = logging_status['TargetBucket']
            target_prefix = logging_status['TargetPrefix', '']

        else:
            logging_info = None
            target_bucket = None
            target_prefix = None

    except ClientError as e:

        print(f"[ERROR]    {bucket_name}: Could not check status ({str(e)})")

    return {"s3":{"is_policy_public": is_policy_public, "is_acl_public": is_acl_public,
            "bpa_blocks_acls": bpa_blocks_acls,"bpa_blocks_policy": bpa_blocks_policy,
            "Bucket_algorithm": algorithm, "km_key": kms_key, "logging_info": logging_info,
            "target_bucket": target_bucket, "target_prefix": target_prefix}}