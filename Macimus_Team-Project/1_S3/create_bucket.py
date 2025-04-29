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
        print(f"{bucket_name} 버킷이 성공적으로 생성되었습니다..")
    except Exception as e:
        print(f"Error creating bucket: {e}")

def set_bucket_policy(bucket_name, policy):
    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(policy)
        )
        print(f"{bucket_name}에 정책이 성공적으로 적용되었습니다.")
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
            "Resource": f"arn:aws:s3:::macimus-logs/AWSLogs/*",
            "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
        },
        {
            "Sid": "AWSCloudTrailBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": f"arn:aws:s3:::macimus-logs"
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
                f"arn:aws:s3:::macimus-data",
                f"arn:aws:s3:::macimus-data/*"
            ]
        }
    ]
}

# 실행
create_bucket("macimus-logs")
set_bucket_policy("macimus-logs", cloudtrail_policy)

create_bucket("macimus-data")
set_bucket_policy("macimus-data", macie_policy)