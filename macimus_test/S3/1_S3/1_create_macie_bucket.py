import boto3
import json

# AWS 클라이언트 초기화
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
kms_client = boto3.client('kms')

# S3 버킷 생성 함수
def create_s3_bucket(bucket_name, region):
    try:
        response = s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}
        )
        print(f"Bucket '{bucket_name}' created successfully.")
        return response
    except Exception as e:
        print(f"Error creating bucket: {e}")
        return None

# S3 버킷 정책 설정 함수
def set_bucket_policy(bucket_name, account_id):
    try:
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "macie.amazonaws.com"
                    },
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "macie.amazonaws.com"
                    },
                    "Action": "s3:ListBucket",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id
                        }
                    }
                }
            ]
        }

        policy_string = json.dumps(bucket_policy)
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=policy_string)
        print(f"Bucket policy set successfully for bucket '{bucket_name}'.")
    except Exception as e:
        print(f"Error setting bucket policy: {e}")

# 버킷 KMS 암호화 설정 함수
def enable_bucket_kms_encryption(bucket_name, kms_key_id):
    try:
        encryption_configuration = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': kms_key_id
                        }
                    }
                ]
            }
        }

        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_configuration
        )
        print(f"KMS encryption enabled for bucket '{bucket_name}' using key '{kms_key_id}'.")
    except Exception as e:
        print(f"Error enabling bucket KMS encryption: {e}")

# 탐지 결과 저장 함수
def save_findings_to_s3(findings, bucket_name, object_key):
    try:
        findings_data = json.dumps(findings, ensure_ascii=False, indent=4)
        s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body=findings_data.encode('utf-8'),
            ContentType='application/json'
        )
        print(f"Findings saved to S3 bucket '{bucket_name}' with key '{object_key}'.")
    except Exception as e:
        print(f"Error saving findings to S3: {e}")

if __name__ == "__main__":
    # 버킷 이름과 리전 설정
    bucket_name = "sensitive-data-reports"
    region = "ap-northeast-2"

    # AWS 계정 ID 가져오기
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]

    # KMS 키 생성 또는 기존 키 사용
    try:
        kms_key_response = kms_client.create_key(
            Description="Key for S3 bucket encryption",
            KeyUsage="ENCRYPT_DECRYPT",
            CustomerMasterKeySpec="SYMMETRIC_DEFAULT"
        )
        kms_key_id = kms_key_response["KeyMetadata"]["KeyId"]
        print(f"KMS key created with ID: {kms_key_id}")
    except Exception as e:
        print(f"Error creating KMS key: {e}")
        exit(1)

    # S3 버킷 생성
    create_response = create_s3_bucket(bucket_name, region)

    if create_response:
        # 버킷 정책 설정
        set_bucket_policy(bucket_name, account_id)

        # 버킷 KMS 암호화 활성화
        enable_bucket_kms_encryption(bucket_name, kms_key_id)

        # 예제 탐지 결과 저장
        example_findings = {
            "id": "example-finding-1",
            "description": "This is a test finding.",
            "severity": "HIGH"
        }
        save_findings_to_s3(example_findings, bucket_name, "macie_findings/example_finding.json")