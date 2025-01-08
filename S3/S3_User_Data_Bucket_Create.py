import boto3
import json

# S3 버킷 생성 함수
def create_s3_bucket(bucket_name, region):
    """
    S3 버킷을 생성합니다.
    :param bucket_name: 생성할 S3 버킷 이름
    :param region: S3 버킷을 생성할 AWS 리전 (예: 'ap-northeast-2' for 서울 리전)
    """
    s3_client = boto3.client('s3', region_name=region)  # S3 클라이언트 생성
    try:
        # S3 버킷 생성 요청
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}  # 리전 설정
        )
        print(f"S3 bucket '{bucket_name}' created successfully in {region} region.")  # 성공 메시지
    except Exception as e:
        # 오류 발생 시 출력
        print(f"Error creating bucket: {e}")

# S3 버킷 정책 생성 함수
def apply_bucket_policy(bucket_name):
    s3_client = boto3.client('s3')

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "macie.amazonaws.com"
                },
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ]
            }
        ]
    }

    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print(f"Bucket policy successfully applied to {bucket_name}")
    except Exception as e:
        print(f"Error applying bucket policy: {e}")        

# 파일 업로드 함수
def upload_file_to_s3(bucket_name, file_name, object_name=None):
    """
    S3 버킷에 파일을 업로드합니다.
    :param bucket_name: 업로드 대상 S3 버킷 이름
    :param file_name: 로컬에 있는 업로드할 파일 경로
    :param object_name: S3 버킷 내 저장할 객체 이름 (옵션: 기본값은 file_name)
    """
    s3_client = boto3.client('s3')  # S3 클라이언트 생성
    if object_name is None:
        object_name = file_name  # object_name이 None인 경우 file_name을 사용
    try:
        # 파일 업로드 요청
        s3_client.upload_file(file_name, bucket_name, object_name)
        print(f"File '{file_name}' uploaded to S3 bucket '{bucket_name}' as '{object_name}'.")  # 성공 메시지
    except Exception as e:
        # 오류 발생 시 출력
        print(f"Error uploading file: {e}")

# 메인 실행
if __name__ == "__main__":
    # S3 버킷 이름 (고유해야 함)
    bucket_name = "macimus-data"
    # S3 버킷이 생성될 AWS 리전
    region = "ap-northeast-2"  # 서울 리전
    # 업로드할 로컬 CSV 파일 경로
    file_name = "dummy_data_random_ids.csv"

    # 1. S3 버킷 생성
    create_s3_bucket(bucket_name, region)

    # 2. 정책 적용
    apply_bucket_policy(bucket_name)

    # 3. 파일 업로드
    upload_file_to_s3(bucket_name, file_name, "dummy_data_random_ids.csv")
