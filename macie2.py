import boto3
import json
from collections import Counter
from time import sleep
import datetime

# Macie 및 S3 클라이언트 초기화
macie2 = boto3.client('macie2', region_name='ap-northeast-2')
s3_client = boto3.client('s3')

# 사용자 지정 데이터 식별자 생성 함수
def create_custom_data_identifier(name, regex, description):
    try:
        response = macie2.create_custom_data_identifier(
            name=name,
            regex=regex,
            description=description,
        )
        print(f"Created Custom Data Identifier '{name}': {response['customDataIdentifierId']}")
        return response['customDataIdentifierId']
    except Exception as e:
        print(f"Error creating custom data identifier '{name}': {e}")
        return None

# 사용자 지정 데이터 식별자 생성
ssn_identifier = create_custom_data_identifier(
    name="SSN-Identifier",
    regex=r"\b\d{6}-\d{7}\b",  # 주민등록번호 형식
    description="Detects Korean SSN format"
)

ccn_identifier = create_custom_data_identifier(
    name="CCN-Identifier",
    regex=r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",  # 4자리-4자리-4자리-4자리 형식
    description="Detects 16-digit credit card numbers in the 4-4-4-4 format"
)


email_identifier = create_custom_data_identifier(
    name="Email-Identifier",
    regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # 이메일 형식
    description="Detects email addresses"
)

name_identifier = create_custom_data_identifier(
    name="Name-Identifier",
    regex=r"[가-힣]{2,4}",  # 한글 이름 (2~4자)
    description="Detects Korean names"
)

# Macie 작업 생성 함수
def create_custom_data_identifier_safe(name, regex, description):
    try:
        # 기존 사용자 지정 데이터 식별자 확인
        existing_identifiers = macie2.list_custom_data_identifiers().get('items', [])
        for identifier in existing_identifiers:
            if identifier['name'] == name:
                print(f"Custom Data Identifier '{name}' already exists: {identifier['id']}")
                return identifier['id']

        # 새로운 데이터 식별자 생성
        response = macie2.create_custom_data_identifier(
            name=name,
            regex=regex,
            description=description,
        )
        print(f"Created Custom Data Identifier '{name}': {response['customDataIdentifierId']}")
        return response['customDataIdentifierId']
    except Exception as e:
        print(f"Error creating custom data identifier '{name}': {e}")
        return None
    
def create_classification_job_with_custom_ids(bucket_name, job_name, custom_ids):
    """
    사용자 지정 데이터 식별자를 포함한 Macie 작업 생성 함수.
    :param bucket_name: 탐지 대상 S3 버킷 이름
    :param job_name: 작업 이름
    :param custom_ids: 사용자 지정 데이터 식별자 ID 리스트
    :return: 작업의 ARN (Amazon Resource Name)
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
            managedDataIdentifierSelector="NONE",  # 기본 데이터 식별자도 포함
        )
        print(f"Created classification job: {response['jobArn']}")
        return response['jobArn']
    except Exception as e:
        print(f"Error creating classification job: {e}")
        return None



# Macie 작업 상태 확인 함수
def wait_for_job_completion(job_arn):
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

# S3 객체 내용 확인 함수
def print_s3_object_content(bucket_name, object_key):
    """
    S3 객체의 내용을 출력하여 디버깅 및 데이터 형식 확인
    """
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        content = response['Body'].read().decode('utf-8')
        print(f"Content of {object_key}:")
        print(content)
    except Exception as e:
        print(f"Error reading object {object_key}: {e}")

# 탐지 결과 저장 함수
def save_findings_to_file(findings, file_name="macie_findings.json"):
    """
    탐지 결과를 JSON 파일로 저장 (datetime 객체 처리 추가)
    """
    try:
        # datetime 객체를 문자열로 변환
        def custom_serializer(obj):
            if isinstance(obj, (datetime.date, datetime.datetime)):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        with open(file_name, "w", encoding="utf-8") as file:
            json.dump(findings, file, ensure_ascii=False, indent=4, default=custom_serializer)
        print(f"Findings saved to {file_name}")
    except Exception as e:
        print(f"Error saving findings to file: {e}")


# 탐지 결과 통계 요약 함수
def summarize_findings(findings):
    """
    탐지 결과를 요약하여 출력 (KeyError 방지 추가)
    """
    severity_counter = Counter()
    sensitive_data_counter = Counter()

    for finding in findings:
        # 'severity' 키가 있는지 확인하고 처리
        severity = finding.get('severity', {}).get('label', 'UNKNOWN')
        severity_counter[severity] += 1

        # 민감 데이터 요약 처리
        sensitive_data = finding.get('sensitiveData', [])
        for data in sensitive_data:
            for detection in data.get('detections', []):
                sensitive_data_counter[detection['type']] += detection['count']

    print("Findings Summary:")
    print("Severity Distribution:")
    for severity, count in severity_counter.items():
        print(f"  {severity}: {count}")

    print("Sensitive Data Types:")
    for data_type, count in sensitive_data_counter.items():
        print(f"  {data_type}: {count}")

def categorize_findings(findings):
    """
    탐지 결과를 민감도별로 분류
    """
    categorized_data = {
        "LOW": [],
        "MEDIUM": [],
        "HIGH": []
    }

    for finding in findings:
        sensitive_data = finding.get('sensitiveData', [])
        severity = 'MEDIUM'  # 기본 민감도

        for data in sensitive_data:
            for detection in data.get('detections', []):
                # SSN 또는 CCN 발견 시 HIGH로 분류
                if detection['type'] in ['SSN-Identifier', 'CCN-Identifier'] and detection['count'] > 0:
                    severity = 'HIGH'
                    break

        # 파일 이름 또는 키 가져오기
        object_key = finding.get('resourcesAffected', {}).get('s3Object', {}).get('key', 'UNKNOWN')
        categorized_data[severity].append(object_key)

    return categorized_data



# 탐지된 S3 객체 태그 지정 함수
def tag_sensitive_objects(findings, bucket_name):
    for finding in findings:
        key = finding.get('resourcesAffected', {}).get('s3Object', {}).get('key', None)
        severity = finding.get('severity', {}).get('label', 'UNKNOWN')

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



# Macie 작업 삭제 함수
def delete_macie_job(job_arn):
    try:
        macie2.delete_classification_job(jobId=job_arn.split('/')[-1])
        print(f"Deleted Macie job: {job_arn}")
    except macie2.exceptions.ResourceNotFoundException:
        print(f"Macie job not found: {job_arn}. It might have been already deleted.")
    except Exception as e:
        print(f"Error deleting Macie job: {e}")


# 전체 실행 흐름
if __name__ == "__main__":
    bucket_name = "test-test-1234"
    job_name = "macimus-test3"

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

                # 탐지 결과 요약
                summarize_findings(findings)

                # 탐지된 객체 태그 지정
                tag_sensitive_objects(findings, bucket_name)

            # 작업 삭제
            delete_macie_job(job_arn)