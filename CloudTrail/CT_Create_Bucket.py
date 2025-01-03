# CloudTrail 전용 버킷 생성
import boto3
from botocore.exceptions import ClientError

def create_s3_bucket(bucket_name, region=None):
    """Create an S3 bucket in a specified region."""
    try:
        # Create bucket
        if region is None:
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client = boto3.client('s3', region_name=region)
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print(f"Bucket '{bucket_name}' created successfully!")
    except ClientError as e:
        print(f"Error: {e}")
        return False
    return True

# Main execution
if __name__ == "__main__":
    bucket_name = "team4-ct-exam1"
    region = "ap-northeast-2"  # 원하는 리전을 입력합니다 (예: 'us-west-1', 'ap-northeast-2' 등)
    create_s3_bucket(bucket_name, region)
