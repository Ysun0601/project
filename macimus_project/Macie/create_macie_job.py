import boto3
import time
import json
from datetime import datetime

# AWS 클라이언트
macie_client = boto3.client('macie2')
sts_client = boto3.client('sts')

# S3 버킷 및 파일 정보
bucket_name = "n-macimus-sensitive-data"
file_name = "sensitive-data-100-krusers.json"

# 1. Macie 활성화 상태 확인
def check_macie_status():
    try:
        response = macie_client.get_macie_session()
        status = response['status']
        print(f"Macie Status: {status}")
        return status
    except Exception as e:
        print(f"Error checking Macie status: {e}")
        return None

# 2. Macie 활성화
def enable_macie():
    try:
        response = macie_client.enable_macie(
            status="ENABLED",
            findingPublishingFrequency="FIFTEEN_MINUTES"  # 탐지 결과 게시 빈도 설정
        )
        print("Amazon Macie has been successfully enabled.")
        print(f"Service Role: {response['serviceRole']}")
    except Exception as e:
        if "ConflictException" in str(e):
            print("Macie is already enabled.")
        else:
            print(f"Error enabling Macie: {e}")

# 3. 사용자 정의 식별자 생성
def create_custom_data_identifier():
    try:
        response = macie_client.create_custom_data_identifier(
            name="CustomUserDataIdentifier",
            description="Identifies custom user data (user_id, name, email, phone_number, address, etc.)",
            regex="(\\b[a-zA-Z0-9]{6}\\b)|"  # user_id (6글자 영문+숫자)
                  "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4})|"  # email
                  "(010-[0-9]{4}-[0-9]{4})|"  # phone_number
                  "(\\b.+시.+동 [0-9]{1,3}\\b)",  # address
            keywords=["user_id", "name", "email", "phone_number", "address"],
            maximumMatchDistance=50  # 민감 데이터가 서로 가까이 있는 경우 탐지 범위
        )
        print(f"Custom Data Identifier Created: {response['id']}")
        return response['id']
    except Exception as e:
        print(f"Error creating custom data identifier: {e}")
        return None

# 4. Macie 탐지 작업 생성 (사용자 정의 식별자 포함)
def create_macie_job_with_custom_identifier(bucket, key, custom_data_id):
    try:
        # 작업 이름에 타임스탬프 추가
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        job_name = f"SensitiveDataClassificationJob-{timestamp}"

        response = macie_client.create_classification_job(
            jobType="ONE_TIME",
            s3JobDefinition={
                "bucketDefinitions": [
                    {
                        "accountId": sts_client.get_caller_identity()["Account"],
                        "buckets": [bucket]
                    }
                ]
            },
            customDataIdentifierIds=[custom_data_id],  # 사용자 정의 식별자 추가
            name=job_name,
            clientToken=str(time.time()),
            managedDataIdentifierSelector="ALL"  # 기본 및 사용자 정의 데이터 식별자 사용
        )
        job_id = response['jobId']
        print(f"Macie Job Created with Custom Identifier: {job_id} with name {job_name}")
        return job_id
    except Exception as e:
        print(f"Error creating Macie job with custom identifier: {e}")
        return None

# 5. Macie 탐지 결과 분석 및 민감도 분류
def analyze_macie_results(job_id):
    try:
        # 작업 상태 확인
        while True:
            status = macie_client.describe_classification_job(jobId=job_id)['jobStatus']
            print(f"Job Status: {status}")
            if status in ["COMPLETE", "CANCELLED", "FAILED"]:
                break
            time.sleep(10)  # 상태 확인 대기

        # 탐지 결과 가져오기
        findings = macie_client.list_findings()
        if not findings["findingIds"]:
            print("No findings detected.")
            return None

        finding_ids = findings["findingIds"]

        # batch_get_findings로 결과 가져오기
        response = macie_client.batch_get_findings(findingIds=finding_ids)
        sensitive_results = response['findings']

        # 민감도 수준별로 분류
        classified_results = {
            "High": [],
            "Moderate": [],
            "Low": []
        }

        for result in sensitive_results:
            severity = result['severity']['description']
            data_class = result.get('classificationDetails', {}).get('result', {}).get('sensitiveData', [])

            for sensitive_data in data_class:
                category = sensitive_data["category"]
                # 높은 민감도
                if category in ["CREDIT_CARD", "IP_ADDRESS"]:
                    classified_results["High"].append(result)
                # 중간 민감도
                elif category in ["NAME", "EMAIL_ADDRESS", "PHONE_NUMBER", "ADDRESS"]:
                    classified_results["Moderate"].append(result)
                # 낮은 민감도
                elif category in ["UNIQUE_ID", "TIME_STAMP"]:
                    classified_results["Low"].append(result)

        print("Sensitive Data Analysis Complete.")
        return classified_results

    except Exception as e:
        print(f"Error analyzing results: {e}")
        return None

# 메인 실행
if __name__ == "__main__":
    # 1. Macie 활성화 상태 확인
    status = check_macie_status()
    if status != "ENABLED":
        print("Macie is not enabled. Enabling now...")
        enable_macie()
    else:
        print("Macie is already enabled.")

    # 2. 사용자 정의 식별자 생성
    print("Creating custom data identifier...")
    custom_data_id = create_custom_data_identifier()
    if not custom_data_id:
        print("Failed to create custom data identifier. Exiting...")
        exit()

    # 3. Macie 탐지 작업 생성 및 실행
    job_id = create_macie_job_with_custom_identifier(bucket_name, file_name, custom_data_id)
    if job_id:
        print("Analyzing Macie results...")
        results = analyze_macie_results(job_id)
        if results:
            print("Sensitive Data Classification Results:")
            print(json.dumps(results, indent=2, ensure_ascii=False))
