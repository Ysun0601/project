import boto3
import uuid
import json

# AWS 클라이언트 초기화
lambda_client = boto3.client('lambda')
eventbridge_client = boto3.client('events')

def add_eventbridge_trigger_to_lambda():
    lambda_function_name = "Macimus_Detect_Unauthorized_S3_Access"
    eventbridge_rule_name = "Macimus_Detect_Unauthorized_Access"

    try:
        # Lambda 함수의 ARN 가져오기
        try:
            lambda_response = lambda_client.get_function(FunctionName=lambda_function_name)
            lambda_function_arn = lambda_response['Configuration']['FunctionArn']
            print(f"Lambda function ARN: {lambda_function_arn}")
        except lambda_client.exceptions.ResourceNotFoundException:
            print(f"Lambda function '{lambda_function_name}' not found.")
            return

        # EventBridge 규칙 존재 여부 확인
        try:
            rule_response = eventbridge_client.describe_rule(Name=eventbridge_rule_name)
            rule_arn = rule_response['Arn']
            print(f"EventBridge rule '{eventbridge_rule_name}' already exists.")
        except eventbridge_client.exceptions.ResourceNotFoundException:
            print(f"EventBridge rule '{eventbridge_rule_name}' does not exist. Creating new rule.")
            rule_response = eventbridge_client.put_rule(
                Name=eventbridge_rule_name,
                EventPattern=json.dumps({
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["s3.amazonaws.com"],
                        "eventName": ["GetObject", "PutObject"]
                    }
                }),
                State="ENABLED",
                Description="Detect unauthorized S3 access via CloudTrail"
            )
            rule_arn = rule_response['RuleArn']
            print(f"EventBridge rule created: {rule_arn}")

        # Lambda 권한 추가
        statement_id = f"{eventbridge_rule_name}-InvokeLambda-{uuid.uuid4()}"
        try:
            lambda_client.add_permission(
                FunctionName=lambda_function_name,
                StatementId=statement_id,
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn
            )
            print(f"Lambda 함수 '{lambda_function_name}'에 EventBridge 규칙 '{eventbridge_rule_name}'에 대한 권한이 추가되었습니다.")
        except lambda_client.exceptions.ResourceConflictException:
            print("Permission already exists for this rule.")

        # EventBridge 규칙에 Lambda 추가
        target_id = f"Target-{uuid.uuid4()}"
        eventbridge_client.put_targets(
            Rule=eventbridge_rule_name,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': lambda_function_arn
                }
            ]
        )
        print(f"EventBridge 규칙 '{eventbridge_rule_name}'이(가) Lambda 함수 '{lambda_function_name}'에 성공적으로 연결되었습니다.")
    except Exception as e:
        print(f"Error adding EventBridge trigger to Lambda: {e}")

# 실행
add_eventbridge_trigger_to_lambda()