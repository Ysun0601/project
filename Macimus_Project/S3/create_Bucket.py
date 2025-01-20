import boto3
import json

# S3 클라이언트 생성
s3_client = boto3.client('s3', region_name='ap-northeast-2')

# 버킷 생성 함수
def create_s3_bucket(bucket_name, region):
    try:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}
        )
        print(f"Bucket {bucket_name} created successfully.")
    except Exception as e:
        print(f"Error creating bucket {bucket_name}: {e}")

# 버킷 정책 설정 함수
def set_bucket_policy(bucket_name, policy):
    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(policy)
        )
        print(f"Policy applied to bucket {bucket_name}.")
    except Exception as e:
        print(f"Error applying policy to bucket {bucket_name}: {e}")

# 민감 정보 저장 버킷
sensitive_bucket_name = "n-macimus-sensitive-data"
sensitive_bucket_policy = {
    "Version": "2012-10-17",
    "Statement": [
        # Macie가 데이터를 읽기 위한 GetObject 권한
        {
            "Effect": "Allow",
            "Principal": {"Service": "macie.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{sensitive_bucket_name}/*"
        },
        # IAM 사용자 Park이 데이터를 업로드/다운로드할 수 있는 PutObject와 GetObject 권한
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::423623825149:user/Park"},
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": f"arn:aws:s3:::{sensitive_bucket_name}/*"
        },
        # 기본적으로 모든 접근을 제한하며, 허용된 IP만 접근 가능
        # {
        #     "Effect": "Deny",
        #     "Principal": "*",
        #     "Action": "s3:*",
        #     "Resource": f"arn:aws:s3:::{sensitive_bucket_name}/*",
        #     "Condition": {
        #         "StringNotEquals": {
        #             "aws:SourceIp": ["121.137.149.43/32"]  # 허용된 IP 대역
        #         }
        #     }
        # }
    ]
}

# 로그 저장 버킷
log_bucket_name = "n-macimus-cloudtrail-logs"
log_bucket_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{log_bucket_name}/AWSLogs/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}

# 버킷 생성 및 정책 설정 실행
region = "ap-northeast-2"
create_s3_bucket(sensitive_bucket_name, region)
set_bucket_policy(sensitive_bucket_name, sensitive_bucket_policy)

create_s3_bucket(log_bucket_name, region)
set_bucket_policy(log_bucket_name, log_bucket_policy)
