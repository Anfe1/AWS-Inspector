import boto3
from botocore.exceptions import ClientError

from src.inspectors import ACTIVE_AUDIT_LOG
from src.inspectors.s3.s3_inspector import check_s3_bucket_public_status

def run_audit():

    print("Initiating AWS resource inspection")

    #TODO: Run the application logic that audits the AWS services


    try:
        # Initialize s3 client
        print("Initiating S3 inspection")
        s3_client = boto3.client("s3")
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        if not buckets:
            print("No buckets found.")
            return

        print(f"{'Bucket Name':<45} | {'Public Block':<12} | {'Encryption':<12} | {'Versioning':<12}")
        print("-" * 90)

        #TODO: Call in inspector functions
        for bucket in buckets:

            bucket_name = bucket['Name']

            s3_results = check_s3_bucket_public_status(bucket_name)



    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return

    if not buckets:
        print("No S3 buckets found.")
        return


    # Results logs
    ACTIVE_AUDIT_LOG.extend([s3_results])

    #TODO: Create a detailed report
    print("\--------- Report ---------")
    for log in ACTIVE_AUDIT_LOG:
        print(f"[{log}]")

if __name__ == "__main__":
    run_audit()