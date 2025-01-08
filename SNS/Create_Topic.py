import boto3

def create_sns_topic(topic_name):
    """
    SNS 주제를 생성합니다.
    :param topic_name: SNS 주제 이름
    :return: 생성된 SNS 주제 ARN
    """
    sns_client = boto3.client('sns')
    try:
        response = sns_client.create_topic(Name=topic_name)
        topic_arn = response['TopicArn']
        print(f"SNS Topic created: {topic_arn}")
        return topic_arn
    except Exception as e:
        print(f"Error creating SNS topic: {e}")

if __name__ == "__main__":
    topic_name = "SensitiveDataAlertTopic"
    topic_arn = create_sns_topic(topic_name)
