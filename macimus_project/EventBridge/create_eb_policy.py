import boto3
import json

eventbridge_client = boto3.client('events')

def create_eventbridge_rule():
    rule_name = "DetectUnauthorizedAccess"
    event_pattern = {
        "source": ["aws.s3"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["s3.amazonaws.com"],
            "eventName": ["GetObject", "PutObject"],
            "requestParameters": {
                "bucketName": ["n3-macimus-sensitive-data"]
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
        print(f"EventBridge rule '{rule_name}' created successfully.")
        return response['RuleArn']
    except Exception as e:
        print(f"Error creating EventBridge rule: {e}")
        return None

# 실행
create_eventbridge_rule()
