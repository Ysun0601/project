import boto3
import json

# S3 버킷 생성 함수
def create_s3_bucket(bucket_name, region_name):
    s3_client = boto3.client('s3', region_name=region_name)
    try:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region_name}
        )
        print(f"S3 bucket '{bucket_name}' created successfully in {region_name} region.")
    except Exception as e:
        print(f"Error creating S3 bucket: {e}")

# S3 버킷 정책 설정 함수 (CloudTrail 로그 저장 허용)
def set_s3_bucket_policy(bucket_name, account_id):
    s3_client = boto3.client('s3')
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            },
            {
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
        print(f"S3 bucket policy updated for '{bucket_name}'.")
    except Exception as e:
        print(f"Error setting bucket policy: {e}")

# CloudTrail 생성 함수
def create_cloudtrail(trail_name, bucket_name):
    cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')
    try:
        response = cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=True
        )
        print(f"CloudTrail '{trail_name}' created successfully.")
        return response
    except Exception as e:
        print(f"Error creating CloudTrail: {e}")

# CloudTrail 로깅 시작 함수
def start_cloudtrail_logging(trail_name):
    cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')
    try:
        cloudtrail_client.start_logging(Name=trail_name)
        print(f"CloudTrail '{trail_name}' logging started.")
    except Exception as e:
        print(f"Error starting CloudTrail logging: {e}")

# 데이터 이벤트 활성화 함수
def enable_data_events(trail_name, sensitive_bucket_name):
    cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')
    try:
        response = cloudtrail_client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': False,
                    'DataResources': [
                        {
                            'Type': 'AWS::S3::Object',
                            'Values': [f"arn:aws:s3:::{sensitive_bucket_name}/*"]
                        }
                    ]
                }
            ]
        )
        print(f"Data events enabled for trail '{trail_name}' on bucket '{sensitive_bucket_name}'.")
    except Exception as e:
        print(f"Error enabling data events: {e}")        

# 실행
if __name__ == "__main__":
    region_name = "ap-northeast-2"  # 서울 리전
    bucket_name = "macimus-cloudtrail-bucket-logs"
    trail_name = "macimus-cloudtrail"
    sensitive_bucket_name = "macimus-data"

    # AWS 계정 ID 가져오기
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()['Account']

    # 1. S3 버킷 생성
    create_s3_bucket(bucket_name, region_name)

    # 2. S3 버킷 정책 설정
    set_s3_bucket_policy(bucket_name, account_id)

    # 3. CloudTrail 생성
    create_cloudtrail(trail_name, bucket_name)

    # 4. CloudTrail 로깅 시작
    start_cloudtrail_logging(trail_name)

    #5. CloudTrail 데이터 이벤트 활성화
    enable_data_events(trail_name, sensitive_bucket_name)
