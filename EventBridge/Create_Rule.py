import boto3
import json

def create_eventbridge_rule_for_s3(rule_name, bucket_name):
    """
    EventBridge 규칙 생성: CloudTrail에서 S3 데이터 접근 이벤트를 감지.
    :param rule_name: EventBridge 규칙 이름
    :param bucket_name: 민감 데이터가 저장된 S3 버킷 이름
    """
    client = boto3.client('events')
    try:
        response = client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps({
                "source": ["aws.cloudtrail"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["s3.amazonaws.com"],
                    "eventName": ["GetObject", "PutObject"],
                    "requestParameters": {
                        "bucketName": [bucket_name]
                    }
                }
            }),
            State="ENABLED"
        )
        print(f"EventBridge rule for S3 access '{rule_name}' created.")
        return response['RuleArn']
    except Exception as e:
        print(f"Error creating EventBridge rule for S3: {e}")


def create_eventbridge_rule_for_macie(rule_name):
    """
    EventBridge 규칙 생성: Macie 작업 완료 이벤트를 감지.
    :param rule_name: EventBridge 규칙 이름
    """
    client = boto3.client('events')
    try:
        response = client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps({
                "source": ["aws.macie"],
                "detail-type": ["Macie Classification Job Completion"]
            }),
            State="ENABLED"
        )
        print(f"EventBridge rule for Macie job completion '{rule_name}' created.")
        return response['RuleArn']
    except Exception as e:
        print(f"Error creating EventBridge rule for Macie: {e}")


def add_lambda_target_to_rule(rule_name, lambda_function_arn):
    """
    EventBridge 규칙에 Lambda 함수를 연결.
    :param rule_name: EventBridge 규칙 이름
    :param lambda_function_arn: Lambda 함수 ARN
    """
    events_client = boto3.client('events')
    lambda_client = boto3.client('lambda')
    try:
        # EventBridge 규칙의 ARN 가져오기
        rule_response = events_client.describe_rule(Name=rule_name)
        rule_arn = rule_response['Arn']

        # EventBridge 규칙의 대상 추가
        events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': '1',
                    'Arn': lambda_function_arn
                }
            ]
        )
        print(f"Lambda function {lambda_function_arn} added as target to EventBridge rule {rule_name}.")

        # Lambda 권한 추가
        lambda_client.add_permission(
            FunctionName=lambda_function_arn,
            StatementId=f"{rule_name}-Invoke",
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=rule_arn
        )
        print(f"Permission added for EventBridge to invoke Lambda function.")
    except Exception as e:
        print(f"Error adding Lambda target: {e}")


# 실행
if __name__ == "__main__":
    # 민감 데이터가 저장된 S3 버킷 이름
    s3_bucket_name = "macimus-data"

    # EventBridge 규칙 이름
    s3_event_rule_name = "SensitiveDataAccessAlert"
    macie_event_rule_name = "MacieJobCompletionAlert"

    # Lambda 함수 ARN
    lambda_function_arn = "arn:aws:lambda:ap-northeast-2:423623825149:function:SensitiveDataAlertHandler"

    # 1. S3 데이터 접근 이벤트를 감지하는 EventBridge 규칙 생성
    create_eventbridge_rule_for_s3(s3_event_rule_name, s3_bucket_name)

    # 2. Macie 작업 완료 이벤트를 감지하는 EventBridge 규칙 생성
    create_eventbridge_rule_for_macie(macie_event_rule_name)

    # 3. EventBridge 규칙과 Lambda 함수를 연결
    add_lambda_target_to_rule(s3_event_rule_name, lambda_function_arn)
    add_lambda_target_to_rule(macie_event_rule_name, lambda_function_arn)
