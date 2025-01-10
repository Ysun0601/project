import boto3
import datetime


# 사용자 정의 데이터 식별자 생성 함수
def create_custom_data_identifier(name, regex, description="Custom Data Identifier", keywords=None):
    """
    사용자 정의 데이터 식별자 생성
    :param name: 데이터 식별자 이름
    :param regex: 정규 표현식
    :param description: 데이터 식별자 설명
    :param keywords: 데이터 식별자 키워드 (옵션)
    :return: 생성된 데이터 식별자 ID
    """
    macie_client = boto3.client('macie2')

    try:
        response = macie_client.create_custom_data_identifier(
            name=name,
            regex=regex,
            description=description,
            keywords=keywords if keywords else []
        )
        identifier_id = response['customDataIdentifierId']
        print(f"Custom Data Identifier created: {identifier_id}")
        return identifier_id
    except Exception as e:
        print(f"Error creating custom data identifier: {e}")
        return None


# Macie 활성화 함수
def enable_macie():
    """
    Macie 활성화
    """
    macie_client = boto3.client('macie2')
    try:
        response = macie_client.enable_macie()
        print("Macie enabled successfully.")
    except macie_client.exceptions.ConflictException:
        print("Macie is already enabled. Proceeding...")
    except Exception as e:
        print(f"Error enabling Macie: {e}")


# 민감 데이터 분류 작업 생성 함수
def create_classification_job(bucket_name, custom_data_identifier_ids):
    """
    Macie 민감 데이터 분류 작업 생성
    :param bucket_name: S3 버킷 이름
    :param custom_data_identifier_ids: 사용자 정의 데이터 식별자 ID 목록
    """
    macie_client = boto3.client('macie2')
    try:
        job_name = f"SensitiveDataScan-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        response = macie_client.create_classification_job(
            jobType='ONE_TIME',
            name=job_name,
            s3JobDefinition={
                'bucketDefinitions': [
                    {'accountId': boto3.client('sts').get_caller_identity()['Account'], 'buckets': [bucket_name]}
                ]
            },
            customDataIdentifierIds=custom_data_identifier_ids
        )
        print(f"Classification job created: {response['jobArn']}")
    except Exception as e:
        print(f"Error creating classification job: {e}")


# 실행
if __name__ == "__main__":
    bucket_name = "macimus-data"  # 탐지 대상 S3 버킷 이름

    # 사용자 정의 데이터 식별자 목록
    identifiers = [
        {"name": "MemberIDIdentifier", "regex": r"\b\d{6}\b", "description": "Matches Member IDs"},
        {"name": "PasswordIdentifier", "regex": r"^[a-zA-Z0-9]{10,}$", "description": "Matches Passwords"},
        {"name": "NameIdentifier", "regex": r"[가-힣]{2,4}", "description": "Matches Korean Names"},
        {"name": "PhoneIdentifier", "regex": r"010-\d{4}-\d{4}", "description": "Matches Korean Phone Numbers"},
        {"name": "EmailIdentifier", "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "description": "Matches Emails"},
        {"name": "SocialLoginIdentifier", "regex": r"google|facebook|kakao|naver", "description": "Matches Social Login Providers"},
        {"name": "DateIdentifier", "regex": r"\d{4}-\d{2}-\d{2}", "description": "Matches Dates"}
    ]

    # 1. 사용자 정의 데이터 식별자 생성
    custom_data_identifier_ids = []
    for identifier in identifiers:
        identifier_id = create_custom_data_identifier(identifier["name"], identifier["regex"], identifier["description"])
        if identifier_id:
            custom_data_identifier_ids.append(identifier_id)

    # 2. Macie 활성화
    enable_macie()

    # 3. 민감 데이터 분류 작업 생성
    if custom_data_identifier_ids:
        create_classification_job(bucket_name, custom_data_identifier_ids)
    else:
        print("No custom data identifiers were created.")
