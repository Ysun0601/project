import boto3

def subscribe_to_sns(topic_arn, protocol, endpoint):
    """
    SNS 주제에 구독 추가.
    :param topic_arn: SNS 주제 ARN
    :param protocol: 구독 프로토콜 (email, sms, https 등)
    :param endpoint: 구독 엔드포인트 (예: 이메일 주소)
    """
    sns_client = boto3.client('sns')
    try:
        response = sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol=protocol,
            Endpoint=endpoint
        )
        print(f"Subscription added: {response['SubscriptionArn']}")
    except Exception as e:
        print(f"Error adding subscription: {e}")

if __name__ == "__main__":
    topic_arn = "arn:aws:sns:ap-northeast-2:423623825149:SensitiveDataAlertTopic"
    protocol = "email"  # 사용할 프로토콜 (email, sms 등)
    endpoint = "studyer123@gmail.com"  # 수신 이메일 주소
    subscribe_to_sns(topic_arn, protocol, endpoint)
