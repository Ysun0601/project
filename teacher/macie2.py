import boto3
import json
from collections import Counter
from time import sleep
import datetime

# Macie 및 S3 클라이언트 초기화
macie2 = boto3.client('macie2', region_name='ap-northeast-2')
s3_client = boto3.client('s3')

# 사용자 지정 데이터 식별자 생성 함수
def create_custom_data_identifier_with_severity(name, regex, description, threshold=1, severity="HIGH"):
    """
    사용자 지정 데이터 식별자를 생성하며 심각도 수준과 발생 임계값을 설정
    """
    try:
        response = macie2.create_custom_data_identifier(
            name=name,
            regex=regex,
            description=description,
            severityLevels=[
                {
                    'occurrencesThreshold': threshold,
                    'severity': severity
                }
            ]
        )
        print(f"Created Custom Data Identifier '{name}': {response['customDataIdentifierId']}")
        return response['customDataIdentifierId']
    except Exception as e:
        print(f"Error creating custom data identifier '{name}': {e}")
        return None


# 사용자 지정 데이터 식별자 생성
ssn_identifier = create_custom_data_identifier_with_severity(
    name="SSN-Identifier",
    regex=r"\b\d{6}-\d{7}\b",  # 주민등록번호 형식
    description="Detects Korean SSN format",
    threshold=1,  # 발생 임계값
    severity="HIGH"  # 심각도 수준
)

ccn_identifier = create_custom_data_identifier_with_severity(
    name="CCN-Identifier",
    regex=r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",  # 신용카드 번호 형식
    description="Detects 16-digit credit card numbers in the 4-4-4-4 format",
    threshold=1,
    severity="HIGH"
)

email_identifier = create_custom_data_identifier_with_severity(
    name="Email-Identifier",
    regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # 이메일 형식
    description="Detects email addresses",
    threshold=1,
    severity="MEDIUM"
)

name_identifier = create_custom_data_identifier_with_severity(
    name="Name-Identifier",
    regex=r"[가-힣]{2,4}",  # 한글 이름 (2~4자)
    description="Detects Korean names",
    threshold=1,
    severity="MEDIUM"
)


# Macie 작업 생성 함수
def create_classification_job_with_custom_ids(bucket_name, job_name, custom_ids):
    """
    사용자 지정 데이터 식별자를 포함한 Macie 작업 생성 함수
    """
    try:
        response = macie2.create_classification_job(
            name=job_name,
            s3JobDefinition={
                "bucketDefinitions": [
                    {
                        "accountId": boto3.client('sts').get_caller_identity()['Account'],
                        "buckets": [bucket_name]
                    }
                ]
            },
            clientToken=f"classification-job-{job_name}",
            jobType="ONE_TIME",
            customDataIdentifierIds=custom_ids,
            managedDataIdentifierSelector="NONE",  # 기본 데이터 식별자 제외
        )
        print(f"Created classification job: {response['jobArn']}")
        return response['jobArn']
    except Exception as e:
        print(f"Error creating classification job: {e}")
        return None


# Macie 작업 상태 확인 함수
def wait_for_job_completion(job_arn):
    """
    Macie 작업 완료 여부 확인
    """
    print("Waiting for Macie job to complete...")
    while True:
        response = macie2.describe_classification_job(jobId=job_arn.split('/')[-1])
        status = response['jobStatus']
        if status in ['COMPLETE', 'CANCELLED']:
            print(f"Job completed with status: {status}")
            return status
        print(f"Current status: {status}. Waiting for 30 seconds...")
        sleep(30)


# 탐지 결과 가져오기 함수
def get_findings():
    """
    Macie 탐지 결과 가져오기
    """
    print("Fetching findings from Macie...")
    findings = []
    response = macie2.list_findings()
    finding_ids = response.get('findingIds', [])
    if not finding_ids:
        print("No findings detected.")
        return findings
    for finding_id in finding_ids:
        detail = macie2.get_findings(findingIds=[finding_id])
        findings.extend(detail['findings'])
    return findings


# 탐지 결과 저장 함수
def save_findings_to_file(findings, file_name="macie_findings.json"):
    """
    탐지 결과를 JSON 파일로 저장
    """
    try:
        def custom_serializer(obj):
            if isinstance(obj, (datetime.date, datetime.datetime)):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        with open(file_name, "w", encoding="utf-8") as file:
            json.dump(findings, file, ensure_ascii=False, indent=4, default=custom_serializer)
        print(f"Findings saved to {file_name}")
    except Exception as e:
        print(f"Error saving findings to file: {e}")


# 탐지된 S3 객체 태그 지정 함수
def tag_sensitive_objects_with_high_priority(findings, bucket_name):
    """
    탐지된 S3 객체에 태그를 추가하여 심각도를 관리
    """
    for finding in findings:
        key = finding.get('resourcesAffected', {}).get('s3Object', {}).get('key', None)
        severity = finding.get('severity', {}).get('label', 'MEDIUM')

        if not key:
            print("No valid key found in finding. Skipping tagging.")
            continue

        try:
            s3_client.put_object_tagging(
                Bucket=bucket_name,
                Key=key,
                Tagging={
                    'TagSet': [
                        {'Key': 'Sensitivity', 'Value': severity}
                    ]
                }
            )
            print(f"Tagged {key} with sensitivity {severity}")
        except Exception as e:
            print(f"Error tagging {key}: {e}")


# 전체 실행 흐름
if __name__ == "__main__":
    bucket_name = "test-test-1234"
    job_name = "macimus-test7"

    # 사용자 지정 데이터 식별자 ID 리스트
    custom_data_identifiers = [ssn_identifier, ccn_identifier, email_identifier, name_identifier]

    # 작업 생성
    job_arn = create_classification_job_with_custom_ids(bucket_name, job_name, custom_data_identifiers)
    if job_arn:
        # 작업 완료 대기
        job_status = wait_for_job_completion(job_arn)

        if job_status == "COMPLETE":
            # 탐지 결과 가져오기
            findings = get_findings()

            if findings:
                # 탐지 결과 저장
                save_findings_to_file(findings)

                # 탐지된 객체 태그 지정
                tag_sensitive_objects_with_high_priority(findings, bucket_name)
