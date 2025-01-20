import boto3
import pandas as pd
import os
import tempfile

# S3 클라이언트 초기화
s3_client = boto3.client('s3')

def preprocess_and_upload_excel_files(bucket_name, object_keys, processed_prefix="processed/"):
    """
    S3에서 엑셀 파일을 가져와 CSV로 변환 후 S3에 업로드.
    """
    uploaded_files = []

    for key in object_keys:
        file_name = os.path.basename(key)
        local_file_path = os.path.join(tempfile.gettempdir(), file_name)

        # Step 1: S3에서 엑셀 파일 다운로드
        try:
            s3_client.download_file(bucket_name, key, local_file_path)
            print(f"다운로드 완료: {key} → {local_file_path}")
        except Exception as e:
            print(f"파일 다운로드 오류: {key} - {e}")
            continue

        # Step 2: 엑셀 파일을 CSV로 변환
        try:
            df = pd.read_excel(local_file_path, sheet_name=None)  # 모든 시트 읽기
            for sheet_name, sheet_df in df.items():
                # CSV 파일 이름 정의
                csv_file_name = f"{os.path.splitext(file_name)[0]}_{sheet_name}.csv"
                s3_csv_key = os.path.join(processed_prefix, csv_file_name)

                # 변환된 데이터를 로컬 CSV로 저장
                csv_file_path = os.path.join(tempfile.gettempdir(), csv_file_name)
                sheet_df.to_csv(csv_file_path, index=False, encoding='utf-8-sig')
                print(f"변환 완료: {local_file_path} ({sheet_name}) → {csv_file_path}")

                # Step 3: 변환된 CSV 파일을 S3로 업로드
                try:
                    s3_client.upload_file(csv_file_path, bucket_name, s3_csv_key)
                    print(f"S3 업로드 완료: {csv_file_path} → s3://{bucket_name}/{s3_csv_key}")
                    uploaded_files.append(s3_csv_key)
                except Exception as e:
                    print(f"S3 업로드 오류: {csv_file_path} - {e}")
        except Exception as e:
            print(f"엑셀 변환 오류: {local_file_path} - {e}")
            continue

    return uploaded_files

if __name__ == "__main__":
    try:
        # S3 버킷 및 폴더 설정
        bucket_name = "n-macimus-sensitive-data"
        processed_prefix = "processed/"

        # S3에서 엑셀 파일 목록 가져오기
        paginator = s3_client.get_paginator('list_objects_v2')
        excel_files = []
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                for obj in page['Contents']:
                    if obj['Key'].endswith(('.xlsx', '.xls')):
                        excel_files.append(obj['Key'])

        print(f"총 {len(excel_files)}개의 엑셀 파일을 찾았습니다.")

        # 엑셀 파일 변환 및 S3 업로드
        uploaded_files = preprocess_and_upload_excel_files(bucket_name, excel_files, processed_prefix)
        print(f"변환 및 업로드된 파일 목록: {uploaded_files}")

    except Exception as e:
        print(f"실행 중 오류 발생: {e}")
