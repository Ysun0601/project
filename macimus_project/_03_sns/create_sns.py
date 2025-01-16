import boto3

# SNS 클라이언트 초기화
sns_client = boto3.client('sns')

def create_sns_topic(topic_name):
    """
    SNS 주제 생성 및 ARN 반환
    """
    try:
        # SNS 주제 생성
        response = sns_client.create_topic(Name=topic_name)
        topic_arn = response['TopicArn']
        print(f"SNS Topic '{topic_name}' created successfully. ARN: {topic_arn}")
        return topic_arn
    except Exception as e:
        print(f"Error creating SNS Topic: {e}")
        return None

def list_sns_topics():
    """
    모든 SNS 주제와 ARN 출력
    """
    try:
        response = sns_client.list_topics()
        topics = response.get('Topics', [])
        print("Existing SNS Topics:")
        for topic in topics:
            print(f"- {topic['TopicArn']}")
    except Exception as e:
        print(f"Error listing SNS Topics: {e}")

def subscribe_to_topic(topic_arn, protocol, endpoint):
    """
    SNS 주제에 구독 추가
    """
    try:
        response = sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol=protocol,
            Endpoint=endpoint
        )
        subscription_arn = response.get('SubscriptionArn', 'PendingConfirmation')
        print(f"Subscription created successfully. ARN: {subscription_arn}")
    except Exception as e:
        print(f"Error subscribing to SNS Topic: {e}")

# 실행
if __name__ == "__main__":
    # 1. SNS 주제 생성
    topic_name = "test2"
    topic_arn = create_sns_topic(topic_name)

    if topic_arn:
        # 2. SNS 주제 목록 출력
        list_sns_topics()

        # 3. 주제에 구독 추가 (예: 이메일 구독)
        protocol = "email"  # 이메일 구독 (다른 옵션: 'sms', 'http', 'https' 등)
        endpoint = "studyer123@gmail.com"  # 이메일 주소 입력
        subscribe_to_topic(topic_arn, protocol, endpoint)