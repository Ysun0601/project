import boto3
import json

region = "ap-northeast-2"

# S3 클라이언트 초기화
s3_client = boto3.client('s3', region_name=region)

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

def set_bucket_policy(bucket_name, policy):
    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(policy)
        )
        print(f"Bucket policy set for '{bucket_name}'.")
    except Exception as e:
        print(f"Error setting bucket policy: {e}")

# CloudTrail 정책
cloudtrail_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::macimus-test-logs/AWSLogs/*",
            "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
        },
        {
            "Sid": "AWSCloudTrailBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": f"arn:aws:s3:::macimus-test-logs"
        }
    ]
}

# Macie 정책
macie_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "macie.amazonaws.com"},
            "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
            "Resource": [
                f"arn:aws:s3:::macimus-test",
                f"arn:aws:s3:::macimus-test/*"
            ]
        }
    ]
}

# 실행
create_bucket("macimus-test-logs")
set_bucket_policy("macimus-test-logs", cloudtrail_policy)

create_bucket("macimus-test")
set_bucket_policy("macimus-test", macie_policy)