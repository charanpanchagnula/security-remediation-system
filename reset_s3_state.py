import boto3
import time
from botocore.exceptions import ClientError

# Configuration
SOURCE_BUCKET = "security-remediation-source-artifacts-dev"
RESULTS_BUCKET = "security-remediation-scan-results-dev"
VECTOR_BUCKET = "security-remediation-guidance"
INDEX_NAME = "remediations"
AWS_REGION = "us-east-1"

def empty_bucket(bucket_name):
    print(f"Emptying bucket: {bucket_name}...")
    s3 = boto3.resource('s3', region_name=AWS_REGION)
    bucket = s3.Bucket(bucket_name)
    try:
        bucket.objects.all().delete()
        print(f"Successfully emptied {bucket_name}")
    except Exception as e:
        print(f"Failed to empty {bucket_name}: {e}")

def reset_vector_index():
    print(f"Resetting Vector Index: {INDEX_NAME} in {VECTOR_BUCKET}...")
    client = boto3.client("s3vectors", region_name=AWS_REGION)
    
    # 1. Delete Index
    try:
        client.delete_index(vectorBucketName=VECTOR_BUCKET, indexName=INDEX_NAME)
        print(f"Deleted index {INDEX_NAME}")
        time.sleep(2) # Wait for propagation
    except ClientError as e:
        if e.response['Error']['Code'] == 'NotFoundException':
            print(f"Index {INDEX_NAME} did not exist.")
        else:
            print(f"Error deleting index: {e}")
    except Exception as e:
        print(f"Error deleting index: {e}")

    # 2. Create Index
    try:
        print(f"Creating index {INDEX_NAME}...")
        client.create_index(
            vectorBucketName=VECTOR_BUCKET,
            indexName=INDEX_NAME,
            dimension=1536,
            distanceMetric="cosine",
            dataType="float32"
        )
        print(f"Successfully recreated index {INDEX_NAME}")
    except Exception as e:
        print(f"Failed to create index: {e}")

if __name__ == "__main__":
    print("Starting S3 Cleanup...")
    empty_bucket(SOURCE_BUCKET)
    empty_bucket(RESULTS_BUCKET)
    reset_vector_index()
    print("Cleanup Complete!")
