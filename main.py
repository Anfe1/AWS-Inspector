import boto3
from botocore.exceptions import ClientError

from src.inspectors import ACTIVE_AUDIT_LOG
from src.inspectors.s3.s3_inspector import check_s3_bucket_public_status

def run_audit():

    print("\nInitiating AWS resource inspection")

    #TODO: Run the application logic that audits the AWS services
    #TODO: Need to reformat for better calling of inspector functions, at the moment the app only calls in s3 inspections
    # it might be best to reformat to include a set of inspector functions to keep the main file cleaner.

    try:
        # Initialize s3 client
        print("\nInitiating S3 inspection")
        s3_client = boto3.client("s3")
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        if not buckets:
            print("No buckets found.")
            return

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