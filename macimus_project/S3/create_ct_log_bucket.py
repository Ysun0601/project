import boto3
import json
# AWS 리전 및 버킷 이름 설정
region = "ap-northeast-2"
bucket_name = "n3-macimus-cloudtrail-logs"

# S3 클라이언트 초기화
s3_client = boto3.client('s3', region_name=region)

# S3 버킷 생성 함수
def create_bucket(bucket_name):
    try:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': region
            }
        )
        print(f"S3 bucket '{bucket_name}' created successfully.")
    except Exception as e:
        print(f"Error creating bucket: {e}")
        

def set_bucket_policy(bucket_name):
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            },
            {
                "Sid": "AWSCloudTrailBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}"
            }
        ]
    }
    
    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print(f"Bucket policy set for '{bucket_name}'.")
    except Exception as e:
        print(f"Error setting bucket policy: {e}")

# 실행
create_bucket(bucket_name)
set_bucket_policy(bucket_name)