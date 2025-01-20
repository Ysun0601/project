import boto3
import json

eventbridge_client = boto3.client('events')

def create_eventbridge_rule_and_target():
    rule_name = "Macimus_Detect_Unauthorized_Access"
    lambda_function_arn = "arn:aws:lambda:ap-northeast-2:423623825149:function:Macimus_Detect_Unauthorized_S3_Access"  # Lambda 함수 ARN

    # Event Pattern 정의
    event_pattern = {
        "source": ["aws.s3"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["s3.amazonaws.com"],
            "eventName": ["GetObject", "PutObject"],
            "requestParameters": {
                "bucketName": ["macimus-data"]
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
        print(f"이벤트 브릿지 규칙 {rule_name}이 성공적으로 생성되었습니다.")

        # Lambda 타겟 연결
        target_response = eventbridge_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": "Macimus_Detect_Unauthorized_S3_Access",
                    "Arn": lambda_function_arn
                }
            ]
        )
        print(f"{rule_name}' 규칙에 대상 Lambda 함수가 추가되었습니다.")
        return {"rule_arn": rule_arn, "target_response": target_response}
    except Exception as e:
        print(f"Error creating EventBridge rule or adding target: {e}")
        return None

# 실행
create_eventbridge_rule_and_target()