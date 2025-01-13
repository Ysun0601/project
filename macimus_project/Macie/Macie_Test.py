import boto3
import time
import json
from datetime import datetime

# AWS 클라이언트
macie_client = boto3.client('macie2')
sts_client = boto3.client('sts')

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

# 3. 사용자 정의 데이터 식별자 생성 함수
def create_custom_data_identifier(name, regex, description="Custom Data Identifier", severity="LOW"):
    try:
        response = macie_client.create_custom_data_identifier(
            name=name,
            regex=regex,
            description=description,
            severityLevels=[
                {
                    "severity": severity,  # 심각도를 매개변수로 설정
                    "occurrencesThreshold": 1
                }
            ]
        )
        identifier_id = response['customDataIdentifierId']
        print(f"Custom Data Identifier created: {identifier_id}")
        return identifier_id
    except Exception as e:
        print(f"Error creating custom data identifier: {e}")
        return None

# 4. Macie 탐지 작업 생성 함수
def create_classification_job(bucket_name, custom_data_identifier_ids):
    try:
        job_name = f"SensitiveDataScan-{datetime.now().strftime('%Y%m%d%H%M%S')}"
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
        job_arn = response['jobArn']
        job_id = job_arn.split("/")[-1]  # jobId 추출
        print(f"Classification job created: {job_id}")
        return job_id
    except Exception as e:
        print(f"Error creating classification job: {e}")
        return None

# 5. Macie 탐지 결과 분석 및 재분류 함수
def analyze_and_reclassify_macie_results(job_id):
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
        if not findings.get["findingIds"]:
            print("No findings detected.")
            return None

        finding_ids = findings["findingIds"]

        # batch_get_findings로 결과 가져오기
        response = macie_client.get_findings(findingIds=finding_ids)
        sensitive_results = response.get['findings', []]

        # 민감도 수준별로 분류
        classified_results = {
            "High": [],
            "Medium": [],
            "Low": []
        }

        for result in sensitive_results:
            severity = result.get('severity', {}).get('description', 'UNKNOWN').upper()
            sensitive_data = result.get('classificationDetails', {}).get('result', {}).get('sensitiveData', [])
            category = sensitive_data[0]['category'] if sensitive_data else "UNKNOWN"

            # 닉네임(NICKNAME)을 강제로 LOW로 재분류
            if category == "NICKNAME":
                print(f"Reclassifying NICKNAME finding to LOW severity: {result['id']}")
                classified_results["Low"].append(result)
            else:
                # 기본 심각도 유지
                classified_results[severity].append(result)

        print("Reclassification complete.")
        return classified_results

    except Exception as e:
        print(f"Error analyzing results: {e}")
        return None

# 메인 실행
if __name__ == "__main__":
    # S3 버킷 및 파일 정보
    bucket_name = "n-macimus-sensitive-data"

    # 사용자 정의 데이터 식별자 목록
    identifiers = [
        {"name": "닉네임", "regex": r"[가-힣]{5}", "description": "5글자 닉네임", "severity": "LOW"},
        {"name": "이름", "regex": r"[가-힣]{2,4}", "description": "대한민국 이름", "severity": "MEDIUM"},
        {"name": "전화번호", "regex": r"010-\d{4}-\d{4}", "description": "대한민국 전화번호", "severity": "MEDIUM"},
        {"name": "이메일", "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "description": "대한민국 이메일", "severity": "MEDIUM"},
        {"name": "주소", "regex": r"\b\d{5}\b", "description": "대한민국 주소", "severity": "MEDIUM"},
        {"name": "로그인 시간", "regex": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", "description": "3번의 로그인 시간 기록", "severity": "MEDIUM"},
        {"name": "내부 IP", "regex": r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})", "description": "로그인 기록 IP", "severity": "HIGH"},
        {"name": "장치명", "regex": r"갤럭시(24|25)|아이폰(15|16)", "description": "로그인 디바이스 장치명", "severity": "MEDIUM"},
        {"name": "카드 유효기간", "regex": r"(0[1-9]|1[0-2])/([2-9][0-9])", "description": "카드 유효기간", "severity": "HIGH"},
        {"name": "카드 보안 코드", "regex": r"(\d:){2,3}\d", "description": "카드 보안코드", "severity": "HIGH"}
    ]

    # 1. Macie 활성화 상태 확인
    status = check_macie_status()
    if status != "ENABLED":
        print("Macie is not enabled. Enabling now...")
        enable_macie()

    # 2. 사용자 정의 식별자 생성
    custom_data_identifier_ids = []
    for identifier in identifiers:
        identifier_id = create_custom_data_identifier(
            identifier["name"], 
            identifier["regex"], 
            identifier["description"], 
            identifier["severity"]
        )
        if identifier_id:
            custom_data_identifier_ids.append(identifier_id)

    # 3. Macie 탐지 작업 생성
    if custom_data_identifier_ids:
        job_id = create_classification_job(bucket_name, custom_data_identifier_ids)
        if job_id:
            # 4. 탐지 결과 분석 및 재분류
            results = analyze_and_reclassify_macie_results(job_id)

            # 5. 결과 출력
            if results:
                print("High severity results:")
                print(json.dumps(results["High"], indent=2, ensure_ascii=False))
                print("Medium severity results:")
                print(json.dumps(results["Medium"], indent=2, ensure_ascii=False))
                print("Low severity results:")
                print(json.dumps(results["Low"], indent=2, ensure_ascii=False))
            else:
                print("No sensitive data findings.")
    else:
        print("No custom data identifiers were created.")
