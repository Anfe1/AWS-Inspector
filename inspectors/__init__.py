# Metadata version
__version__ = "1.0.0"

from .s3 import check_s3_bucket_public_status

print(f"Initializing AWS Compliance Engine v{__version__}...")
ACTIVE_AUDIT_LOG = []