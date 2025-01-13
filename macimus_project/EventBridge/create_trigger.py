import boto3
import json

# EventBridge 클라이언트 초기화
eventbridge_client = boto3.client('events')

def add_eventbridge_trigger():
    rule_name = "DetectUnauthorizedS3AccessRule"

    # EventBridge 규칙 생성
    event_pattern = {
        "source": ["aws.s3"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["s3.amazonaws.com"],
            "eventName": ["GetObject", "PutObject"]
        }
    }

    try:
        # 규칙 생성
        rule_response = eventbridge_client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State="ENABLED",
            Description="Detect unauthorized S3 access via CloudTrail"
        )
        rule_arn = rule_response['RuleArn']
        print(f"EventBridge rule created: {rule_name} (ARN: {rule_arn})")

        # Lambda 함수를 규칙의 타겟으로 추가
        lambda_client = boto3.client('lambda')
        function_name = "DetectUnauthorizedS3Access"
        target_id = "LambdaTarget"

        eventbridge_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": lambda_client.get_function(FunctionName=function_name)['Configuration']['FunctionArn']
                }
            ]
        )
        print(f"Lambda function '{function_name}' added as target to EventBridge rule '{rule_name}'.")
    except Exception as e:
        print(f"Error adding EventBridge trigger: {e}")

# 실행
add_eventbridge_trigger()
