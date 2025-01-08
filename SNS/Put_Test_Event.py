import boto3
import json

def put_test_event(rule_name):
    """
    EventBridge 규칙을 트리거하는 테스트 이벤트를 생성합니다.
    """
    events_client = boto3.client('events')
    try:
        response = events_client.put_events(
            Entries=[
                {
                    'Source': 'aws.macie',
                    'DetailType': 'Macie Alert',
                    'Detail': json.dumps({
                        "eventSource": "s3.amazonaws.com",
                        "eventName": "GetObject",
                        "userIdentity": {"arn": "arn:aws:iam::423623825149:user/TestUser"},
                        "requestParameters": {"bucketName": "macimus-data"}
                    }),
                    'EventBusName': 'default'
                }
            ]
        )
        print(f"Test event sent: {response}")
    except Exception as e:
        print(f"Error sending test event: {e}")

if __name__ == "__main__":
    put_test_event("SensitiveDataAccessAlert")
