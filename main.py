from inspectors import check_s3_bucket_public_status, ACTIVE_AUDIT_LOG

def run_audit():

    print("Initiating AWS resource inspection")

    #TODO: Run the application logic that audits the AWS services

    # Results logs
    ACTIVE_AUDIT_LOG.extend([])

    print("\--- Report ---")
    for log in ACTIVE_AUDIT_LOG:
        print(f"[{log['status']}] {log['check']}")

if __name__ == "__main__":
    run_audit()