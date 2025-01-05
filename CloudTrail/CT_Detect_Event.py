import json
from datetime import datetime

def detect_suspicious_events(events, suspicious_ips=None, suspicious_events=None, time_range=None):
    """
    이상 행동 탐지 로직.
    :param events: CloudTrail에서 파싱된 이벤트 리스트
    :param suspicious_ips: 비정상적인 IP 주소 리스트
    :param suspicious_events: 의심스러운 이벤트 이름 리스트
    :param time_range: 비정상 시간대 (tuple, 예: (0, 6))
    :return: 탐지된 비정상 이벤트 리스트
    """
    suspicious_ips = suspicious_ips or []
    suspicious_events = suspicious_events or []
    suspicious = []

    for event in events:
        event_name = event.get('eventName', '')
        source_ip = event.get('sourceIPAddress', '')
        event_time = event.get('eventTime', '')
        user_name = event.get('userIdentity', {}).get('userName', '')

        # 비정상 IP 탐지
        if source_ip in suspicious_ips:
            suspicious.append({
                "reason": "Suspicious IP detected",
                "event": event
            })

        # 의심스러운 이벤트 탐지
        if event_name in suspicious_events:
            suspicious.append({
                "reason": "Suspicious event name detected",
                "event": event
            })

        # 비정상 시간대 탐지
        if time_range:
            event_time_obj = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%SZ")
            if not (time_range[0] <= event_time_obj.hour < time_range[1]):
                suspicious.append({
                    "reason": "Event occurred in abnormal time range",
                    "event": event
                })

    return suspicious

def save_suspicious_events(suspicious_events, output_path):
    """
    탐지된 비정상 이벤트를 파일로 저장.
    :param suspicious_events: 탐지된 이벤트 리스트
    :param output_path: 저장할 파일 경로
    """
    try:
        with open(output_path, 'w') as outfile:
            json.dump(suspicious_events, outfile, indent=4)
        print(f"Suspicious events saved to {output_path}")
    except Exception as e:
        print(f"Error saving suspicious events: {e}")

if __name__ == "__main__":
    # 이전 코드에서 가져온 파싱된 이벤트 리스트
    logs_path = "./cloudtrail_logs"
    parsed_events_file = "./parsed_events.json"

    # 기존에 파싱된 이벤트 로드
    with open(parsed_events_file, 'r') as infile:
        all_events = json.load(infile)

    # 비정상 행동 조건
    suspicious_ips = ["203.0.113.5", "192.0.2.10"]  # 비정상 IP
    suspicious_events = ["DeleteObject", "PutObjectAcl"]  # 의심스러운 이벤트 이름
    time_range = (0, 6)  # 비정상 시간대: 자정 ~ 오전 6시

    # 비정상 행동 탐지
    suspicious_events_detected = detect_suspicious_events(
        all_events,
        suspicious_ips=suspicious_ips,
        suspicious_events=suspicious_events,
        time_range=time_range
    )

    # 결과 출력
    print(f"Suspicious events found: {len(suspicious_events_detected)}")
    for suspicious_event in suspicious_events_detected:
        print(json.dumps(suspicious_event, indent=4))

    # 결과 저장
    output_path = "./suspicious_events.json"
    save_suspicious_events(suspicious_events_detected, output_path)
