import boto3
import pandas as pd
import os
import tempfile
import json
from collections import Counter
import datetime
import re
from time import sleep

# Macie 및 S3 클라이언트 초기화
macie2 = boto3.client('macie2', region_name='ap-northeast-2')
s3_client = boto3.client('s3')

# Step 1: 엑셀 파일을 CSV로 변환
def preprocess_excel_files(bucket_name, object_keys, output_folder=None):
    """
    S3에서 엑셀 파일을 가져와 CSV로 변환 후 반환.
    """
    if output_folder is None:
        output_folder = tempfile.gettempdir()  # OS에 맞는 기본 임시 디렉토리

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)  # 디렉토리 생성

    converted_files = []
    for key in object_keys:
        # S3에서 파일 다운로드
        file_name = os.path.basename(key).split('?')[0]  # 확장자 뒤 데이터 제거
        local_file_path = os.path.join(output_folder, file_name)

        try:
            s3_client.download_file(bucket_name, key, local_file_path)
        except Exception as e:
            print(f"파일 다운로드 오류: {key} - {e}")
            continue

        # 엑셀 파일을 CSV로 변환
        try:
            df = pd.read_excel(local_file_path, sheet_name=None)  # 모든 시트 읽기
            for sheet_name, sheet_df in df.items():
                converted_file_path = os.path.join(output_folder, f"{os.path.splitext(file_name)[0]}_{sheet_name}.csv")
                sheet_df.to_csv(converted_file_path, index=False, encoding='utf-8-sig')
                print(f"Converted {key} ({sheet_name}) to {converted_file_path}")
                converted_files.append(converted_file_path)
        except Exception as e:
            print(f"엑셀 변환 오류: {local_file_path} - {e}")
            continue

    return converted_files

# Step 2: Macie 사용자 지정 데이터 식별자 생성
def create_custom_data_identifier_with_severity(name, regex, description, threshold=1, severity="HIGH", tags=None):
    """
    사용자 지정 데이터 식별자를 생성하며 심각도 수준, 발생 임계값, 태그를 설정
    """
    try:
        payload = {
            "name": name,
            "regex": regex,
            "description": description,
            "severityLevels": [
                {
                    "occurrencesThreshold": threshold,
                    "severity": severity
                }
            ]
        }
        if tags:
            payload["tags"] = tags
        response = macie2.create_custom_data_identifier(**payload)
        print(f"생성된 사용자 지정 데이터 식별자 '{name}': {response['customDataIdentifierId']}")
        return response['customDataIdentifierId']
    except Exception as e:
        print(f"데이터 식별자 생성 오류 '{name}': {e}")
        return None

def create_all_identifiers():
    """
    모든 사용자 지정 데이터 식별자를 생성하고 반환하는 함수
    """
    identifiers = {}
    identifiers['ssn'] = create_custom_data_identifier_with_severity(
        name="SSN-Identifier",
        regex=r"\b\d{6}-\d{7}\b",  # 주민등록번호 형식
        description="주민등록번호 형식 탐지",
        threshold=1,
        severity="HIGH",
        tags={"Sensitivity": "HIGH"}
    )
    identifiers['ccn'] = create_custom_data_identifier_with_severity(
        name="CCN-Identifier",
        regex=r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",  # 신용카드 번호 형식
        description="신용카드 번호 형식 탐지",
        threshold=1,
        severity="HIGH",
        tags={"Sensitivity": "HIGH"}
    )
    identifiers['email'] = create_custom_data_identifier_with_severity(
        name="Email-Identifier",
        regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # 이메일 형식
        description="이메일 주소 탐지",
        threshold=1,
        severity="MEDIUM",
        tags={"Sensitivity": "MEDIUM"}
    )
    identifiers['name'] = create_custom_data_identifier_with_severity(
        name="Name-Identifier",
        regex=r"[가-힣]{2,4}",  # 한글 이름 형식
        description="한글 이름 탐지",
        threshold=1,
        severity="MEDIUM",
        tags={"Sensitivity": "MEDIUM"}
    )
    return identifiers

# Step 3: Macie 작업을 실행하여 탐지 결과 가져오기
def get_findings():
    """
    Macie 탐지 결과 가져오기
    """
    findings = []
    try:
        start_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp() - 24 * 3600)
        paginator = macie2.get_paginator('list_findings')
        finding_criteria = {
            'criterion': {
                'type': {'eq': ['SENSITIVE_DATA']},
                'severity.description': {'eq': ['High']},
                'createdAt': {'gte': start_time}
            }
        }

        for page in paginator.paginate(findingCriteria=finding_criteria, maxResults=100):
            if page.get('findingIds'):
                response = macie2.get_findings(findingIds=page['findingIds'])
                if response.get('findings'):
                    findings.extend(response['findings'])
                    print(f"- {len(response['findings'])}개의 결과를 가져왔습니다.")

    except Exception as e:
        print(f"탐지 결과 조회 오류: {e}")
    return findings

# Step 4: CSV 파일 업로드 및 태그 업데이트
def analyze_and_tag_csv_files(bucket_name, converted_files):
    """
    변환된 CSV 파일을 Macie로 분석하고 민감도를 기준으로 태그를 업데이트.
    """
    for file_path in converted_files:
        file_name = os.path.basename(file_path)
        s3_key = f"processed/{file_name}"

        # S3에 업로드
        try:
            s3_client.upload_file(file_path, bucket_name, s3_key)
            print(f"Uploaded {file_path} to S3 {bucket_name}/{s3_key}")
        except Exception as e:
            print(f"파일 업로드 오류: {file_path} - {e}")
            continue

        # Macie 탐지 수행
        try:
            sensitivity = analyze_object_content(bucket_name, s3_key)
            s3_client.put_object_tagging(
                Bucket=bucket_name,
                Key=s3_key,
                Tagging={
                    'TagSet': [
                        {'Key': 'sensitivity', 'Value': sensitivity}
                    ]
                }
            )
            print(f"태그 업데이트 완료: {s3_key} - 민감도: {sensitivity}")
        except Exception as e:
            print(f"태그 업데이트 오류: {s3_key} - {e}")

def analyze_object_content(bucket_name, key):
    """
    S3 객체의 내용을 분석하여 민감도 수준을 결정.
    """
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        content_bytes = response['Body'].read()

        # 다양한 인코딩 시도
        encodings = ['utf-8', 'euc-kr', 'cp949', 'iso-8859-1']
        content = None
        for encoding in encodings:
            try:
                content = content_bytes.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            print(f"인코딩 실패: {key}")
            return "LOW"

        # 민감 정보 패턴 정의
        patterns = {
            'HIGH': [r"\b\d{6}-\d{7}\b", r"\b\d{4}-\d{4}-\d{4}-\d{4}\b"],
            'MEDIUM': [r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", r"[가-힣]{2,4}"]
        }

        # 패턴 매칭
        matches = {'HIGH': 0, 'MEDIUM': 0}
        for level, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches[level] += len(re.findall(pattern, content))

        # 민감도 결정
        if matches['HIGH'] > 0:
            return "HIGH"
        elif matches['MEDIUM'] > 0:
            return "MEDIUM"
        return "LOW"

    except Exception as e:
        print(f"객체 분석 오류 {key}: {e}")
        return "LOW"

# 전체 실행 흐름
if __name__ == "__main__":
    try:
        bucket_name = "n-macimus-sensitive-data"  # 실제 S3 버킷 이름 설정
        output_folder = tempfile.gettempdir()

        # S3에서 엑셀 파일 목록 가져오기
        paginator = s3_client.get_paginator('list_objects_v2')
        excel_files = []
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                for obj in page['Contents']:
                    if obj['Key'].endswith(('.xlsx', '.xls')):
                        excel_files.append(obj['Key'])

        print(f"총 {len(excel_files)}개의 엑셀 파일을 찾았습니다.")

        # 엑셀 파일 변환
        converted_files = preprocess_excel_files(bucket_name, excel_files, output_folder)
        print(f"변환된 CSV 파일: {converted_files}")

        # Macie 분석 및 태그 업데이트
        analyze_and_tag_csv_files(bucket_name, converted_files)

    except Exception as e:
        print(f"실행 중 오류 발생: {e}")
