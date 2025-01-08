import json
import boto3

def lambda_handler(event, context):
    """
    Lambda 함수. EventBridge로부터 이벤트를 받아 처리.
    """
    sns_client = boto3.client('sns')
    alert_topic_arn = "arn:aws:sns:ap-northeast-2:423623825149:SensitiveDataAlertTopic"

    try:
        # 이벤트 로그 출력
        print("Event received:", json.dumps(event, indent=4))
        event_detail = event['detail']
        
        # 알림 메시지 작성
        message = (
            f"Sensitive Data Access Detected!\n"
            f"Event Source: {event_detail['eventSource']}\n"
            f"Event Name: {event_detail['eventName']}\n"
            f"Bucket: {event_detail['requestParameters']['bucketName']}\n"
            f"Requester: {event_detail['userIdentity']['arn']}\n"
        )

        # SNS로 알림 전송
        sns_client.publish(
            TopicArn=alert_topic_arn,
            Subject="Sensitive Data Access Alert",
            Message=message
        )
        print("Alert sent via SNS.")
    except Exception as e:
        print(f"Error processing event: {e}")
