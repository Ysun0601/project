import boto3
import gzip
import json
import os

s3_client = boto3.client('s3', region_name='ap-northeast-2')

def process_log_file(bucket_name, log_key):
    """
    S3에서 CloudTrail 로그 파일 다운로드 및 분석.
    :param bucket_name: S3 버킷 이름
    :param log_key: S3 객체 키
    """
    try:
        # 로컬 경로 설정 (Windows 호환)
        local_dir = "C:/temp"
        os.makedirs(local_dir, exist_ok=True)
        local_file = os.path.join(local_dir, log_key.split('/')[-1])

        # 파일 다운로드
        print(f"Downloading file: {log_key} to {local_file}")
        s3_client.download_file(bucket_name, log_key, local_file)

        # 파일이 존재하는지 확인
        if not os.path.exists(local_file):
            print(f"File not found after download: {local_file}")
            return

        # GZIP 파일 열기
        with gzip.open(local_file, 'rt') as f:
            log_data = json.load(f)
            analyze_logs(log_data)

    except Exception as e:
        print(f"Error processing log file {log_key}: {e}")

def analyze_logs(log_data):
    """
    CloudTrail 로그 데이터 분석.
    """
    try:
        for record in log_data.get('Records', []):
            event_name = record.get('eventName')
            source_ip = record.get('sourceIPAddress')
            user_identity = record.get('userIdentity', {}).get('arn')
            print(f"Event: {event_name}, IP: {source_ip}, User ARN: {user_identity}")
    except Exception as e:
        print(f"Error analyzing log data: {e}")

# 실행
if __name__ == "__main__":
    bucket_name = "n-macimus-cloudtrail-logs"
    log_key = "AWSLogs/423623825149/CloudTrail/ap-northeast-2/2025/01/07/423623825149_CloudTrail_ap-northeast-2_20250107T0705Z_uJcKrePHXs16bLTe.json.gz"

    process_log_file(bucket_name, log_key)
    
    

