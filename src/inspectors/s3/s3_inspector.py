import boto3
from botocore.exceptions import ClientError

#TODO: Finish logging system
#TODO: Refactor function for better use, testing, tracking

def check_s3_bucket_public_status(s3_client, bucket_name: str) -> dict:

    print(f"\nAnalyzing bucket: {bucket_name}")

    # Check Bucket Policy
    print("|---------Initiating Bucket Policy Check---------|")
    try:
        # Retrieve the bucket policy and checks if the policy is public
        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        is_policy_public = policy_status.get('PolicyStatus', {}).get('IsPublic', False)

        return {"check": "public_status",
                "is_public": is_policy_public,
                "details": "Bucket is public" if is_policy_public else "Bucket is private"}

    # Error handling for policy
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            is_policy_public = False

            return {"check": "public_status",
                    "is_public": is_policy_public,
                    "details": "No bucket policy found."}

        else:
            is_policy_public = None

            return {"check": "public_status",
                    "is_public": is_policy_public,
                    "details": print(f"Error checking policy status: {e}")}

def check_s3_bucket_acl(s3_client, bucket_name: str) -> dict:

    # Check Bucket ACLs
    is_acl_public = False

    try:
        print("|---------Initiating Bucket ACL Check---------|")
        # Retrieves the bucket ACL, checks grants and grantee groups URI to determine if the ACL is public.
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)

        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})

            if grantee.get('Type') == 'Group' and grantee.get('URI') in [
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://amazonaws.com'
            ]:
                is_acl_public = True
                return {"check": "Bucket ACLs",
                        "is_public": is_acl_public,
                        "details": "Bucket has ALCs enabled." if is_acl_public else "Bucket has ACLs disabled."}

    except ClientError as e:
        print(f"Error checking ACL: {e}")

def check_s3_bucket_bpa_configuration(s3_client, bucket_name: str) -> dict:

    # Check Block Public Access
    bpa_blocks_acls = False
    bpa_blocks_policy = False

    try:
        print("|---------Initiating BPA configuration Check---------|")
        # Retrieves the bpa configuration for the s3, determines if the public policies are being blocked or restricted
        bpa =  s3_client.get_public_access_block(Bucket=bucket_name)
        config = bpa.get('PublicAccessBlockConfiguration', {})

        bpa_blocks_acls = config.get('IgnorePublicAcls', False) or config.get('BlockPublicAcls', False)
        bpa_blocks_policy = config.get('RestrictPublicBuckets', False) or config.get('BlockPublicPolicy', False)

    except ClientError as e:

        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlock':
            pass
        else:
            print(f'Error checking BPA: {e}')

def check_s3_bucket_encryption(s3_client, bucket_name: str) -> dict:

    # Check Encryption configuration
    try:
        print("|---------Initiating Bucket Encryption Check---------|")
        # Retrieves the bucket encryption configuration and checks if any of the encryption settings are enabled.

        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
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

def check_s3_bucket_logging(s3_client, bucket_name: str) -> dict:

    # Check Bucket Logging
    try:
        print("|---------Initiating Bucket Logging Check---------|")
        # Check if logging is enabled and extracts loggin info
        logging_status =  s3_client.get_bucket_logging(Bucket=bucket_name)

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

