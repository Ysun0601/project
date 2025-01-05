import json
import os
import boto3

def download_logs(bucket_name, prefix, download_path):
    """S3에서 로그 파일 다운로드."""
    s3_client = boto3.client('s3')
    os.makedirs(download_path, exist_ok=True)

    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if 'Contents' in response:
            for obj in response['Contents']:
                file_name = obj['Key'].split('/')[-1]
                file_path = os.path.join(download_path, file_name)
                s3_client.download_file(bucket_name, obj['Key'], file_path)
                print(f"Downloaded: {file_path}")
        else:
            print("No logs found.")
    except Exception as e:
        print(f"Error downloading logs: {e}")

def parse_logs(logs_path):
    """CloudTrail 로그에서 이벤트 파싱."""
    events = []
    for file_name in os.listdir(logs_path):
        if file_name.endswith(".json"):
            file_path = os.path.join(logs_path, file_name)
            try:
                with open(file_path, 'r') as log_file:
                    data = json.load(log_file)
                    events.extend(data.get('Records', []))
            except Exception as e:
                print(f"Error reading {file_name}: {e}")
    return events

def save_parsed_events(events, output_path):
    """파싱된 이벤트를 JSON 파일로 저장."""
    try:
        with open(output_path, 'w') as outfile:
            json.dump(events, outfile, indent=4)
        print(f"Parsed events saved to {output_path}")
    except Exception as e:
        print(f"Error saving parsed events: {e}")

def filter_events(events, event_name=None, ip_address=None, user_name=None):
    """특정 조건으로 이벤트 필터링."""
    filtered_events = [
        event for event in events
        if (not event_name or event.get('eventName') == event_name) and
           (not ip_address or event.get('sourceIPAddress') == ip_address) and
           (not user_name or event.get('userIdentity', {}).get('userName') == user_name)
    ]
    return filtered_events

if __name__ == "__main__":
    # S3 버킷 및 로그 경로 설정
    bucket_name = "team4-ct-exam1"
    prefix = "AWSLogs/423623825149/CloudTrail/ap-northeast-2/2025/01/05/"
    download_path = "./cloudtrail_logs"
    parsed_events_file = "./parsed_events.json"  # 파싱된 이벤트 저장 파일 경로

    # 로그 다운로드
    download_logs(bucket_name, prefix, download_path)

    # 로그 파싱 및 저장
    all_events = parse_logs(download_path)
    save_parsed_events(all_events, parsed_events_file)

    # 특정 조건으로 이벤트 필터링
    suspicious_events = filter_events(
        all_events,
        event_name="DeleteObject",  # 파일 삭제 이벤트 탐지
        ip_address="203.0.113.5",  # 비정상 IP 주소 필터링
    )

    # 결과 출력
    print(f"Suspicious events found: {len(suspicious_events)}")
    for event in suspicious_events:
        print(json.dumps(event, indent=4))
