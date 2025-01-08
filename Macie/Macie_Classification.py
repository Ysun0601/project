import boto3
import datetime

# Macie 활성화 함수
def enable_macie():
    macie_client = boto3.client('macie2')
    try:
        response = macie_client.enable_macie()
        print("Macie enabled successfully.")
    except macie_client.exceptions.ConflictException:
        print("Macie is already enabled. Proceeding...")
    except Exception as e:
        print(f"Error enabling Macie: {e}")

# 민감 데이터 분류 작업 생성 함수
def create_classification_job(bucket_name):
    macie_client = boto3.client('macie2')
    try:
        # 고유한 작업 이름 생성 (현재 시간 기반)
        job_name = f"SensitiveDataScan-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        response = macie_client.create_classification_job(
            jobType='ONE_TIME',
            name=job_name,
            s3JobDefinition={
                'bucketDefinitions': [
                    {'accountId': boto3.client('sts').get_caller_identity()['Account'], 'buckets': [bucket_name]}
                ]
            },
            clientToken='unique-client-token'
        )
        print(f"Classification job created: {response['jobArn']}")
    except Exception as e:
        print(f"Error creating classification job: {e}")

# 실행
if __name__ == "__main__":
    bucket_name = "macimus-data"

    # Macie 활성화 및 민감 데이터 스캔 작업 생성
    enable_macie()
    create_classification_job(bucket_name)
