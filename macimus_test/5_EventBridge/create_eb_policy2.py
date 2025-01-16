import boto3
import json

eventbridge_client = boto3.client('events')

def create_eventbridge_rule_and_target():
    rule_name = "DetectUnauthorizedAccess"
    lambda_function_arn = "arn:aws:lambda:ap-northeast-2:423623825149:function:DetectUnauthorizedS3Access"  # Lambda 함수 ARN

    # Event Pattern 정의
    event_pattern = {
        "source": ["aws.s3"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["s3.amazonaws.com"],
            "eventName": ["GetObject", "PutObject"],
            "requestParameters": {
                "bucketName": ["macimus-test"]
            }
        }
    }

    try:
        # EventBridge 규칙 생성
        response = eventbridge_client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State="ENABLED",
            Description="Detect unauthorized access to sensitive bucket via CloudTrail"
        )
        rule_arn = response['RuleArn']
        print(f"EventBridge rule '{rule_name}' created successfully.")

        # Lambda 타겟 연결
        target_response = eventbridge_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": "DetectUnauthorizedLambda",
                    "Arn": lambda_function_arn
                }
            ]
        )
        print(f"Target Lambda function added to rule '{rule_name}'.")
        return {"rule_arn": rule_arn, "target_response": target_response}
    except Exception as e:
        print(f"Error creating EventBridge rule or adding target: {e}")
        return None

# 실행
create_eventbridge_rule_and_target()
