import boto3
import pandas as pd
import os
import tempfile
import json
import datetime
from time import sleep
from collections import Counter
import re

# AWS 클라이언트 초기화
macie2 = boto3.client('macie2', region_name='ap-northeast-2')
s3_client = boto3.client('s3')

def preprocess_excel_files(bucket_name, object_keys, output_folder=None):
    """
    S3에서 엑셀 파일을 가져와 CSV로 변환 후 반환.
    """
    if output_folder is None:
        output_folder = tempfile.gettempdir()

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    converted_files = []
    for key in object_keys:
        file_name = os.path.basename(key)
        local_file_path = os.path.join(output_folder, file_name)

        # S3에서 파일 다운로드
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
                converted_files.append((converted_file_path, f"processed/{os.path.basename(converted_file_path)}"))
        except Exception as e:
            print(f"엑셀 변환 오류: {local_file_path} - {e}")
            continue

    return converted_files

def upload_converted_files(bucket_name, converted_files):
    """
    변환된 CSV 파일을 S3로 업로드.
    """
    uploaded_keys = []
    for local_path, s3_key in converted_files:
        try:
            s3_client.upload_file(local_path, bucket_name, s3_key)
            uploaded_keys.append(s3_key)
            print(f"업로드 완료: {local_path} → {s3_key}")
        except Exception as e:
            print(f"파일 업로드 오류: {local_path} - {e}")
    return uploaded_keys

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
            'HIGH': [
                r"\b\d{6}-\d{7}\b",  # 주민등록번호
                r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",  # 신용카드 번호
            ],
            'MEDIUM': [
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # 이메일
                r"[가-힣]{2,4}",  # 한글 이름
            ]
        }

        # 각 패턴별 매칭 횟수 확인
        matches = {'HIGH': 0, 'MEDIUM': 0}
        for level, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches[level] += len(re.findall(pattern, content))

        # 민감도 수준 결정
        if matches['HIGH'] > 0:
            return "HIGH"
        elif matches['MEDIUM'] > 0:
            return "MEDIUM"
        return "LOW"

    except Exception as e:
        print(f"객체 분석 오류 {key}: {e}")
        return "LOW"

def update_object_tags(bucket_name, keys):
    """
    변환된 CSV 파일에 대해 민감도 분석 및 태그 추가.
    """
    for key in keys:
        print(f"\n객체 분석 중: {key}")

        # 민감도 분석
        sensitivity = analyze_object_content(bucket_name, key)

        # S3 객체 태그 업데이트
        try:
            s3_client.put_object_tagging(
                Bucket=bucket_name,
                Key=key,
                Tagging={
                    'TagSet': [
                        {'Key': 'sensitivity', 'Value': sensitivity}
                    ]
                }
            )
            print(f"태그 업데이트 완료: {key} - 민감도: {sensitivity}")
        except Exception as e:
            print(f"태그 업데이트 오류: {key} - {e}")

# 전체 실행 흐름
if __name__ == "__main__":
    try:
        bucket_name = "n-macimus-sensitive-data"
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

        # 변환된 파일 업로드
        uploaded_keys = upload_converted_files(bucket_name, converted_files)
        print(f"업로드된 파일 키: {uploaded_keys}")

        # 업로드된 파일에 대해 태그 업데이트
        update_object_tags(bucket_name, uploaded_keys)

    except Exception as e:
        print(f"실행 중 오류 발생: {e}")
