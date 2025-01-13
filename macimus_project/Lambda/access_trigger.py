import boto3

# AWS 클라이언트 초기화
lambda_client = boto3.client('lambda')
eventbridge_client = boto3.client('events')

def add_eventbridge_trigger_to_lambda():
    """
    EventBridge 규칙을 Lambda 함수의 트리거로 추가
    """
    lambda_function_name = "DetectUnauthorizedS3Access"  # Lambda 함수 이름
    eventbridge_rule_name = "DetectUnauthorizedAccess"   # EventBridge 규칙 이름

    try:
        # Lambda 함수의 ARN 가져오기
        lambda_response = lambda_client.get_function(FunctionName=lambda_function_name)
        lambda_function_arn = lambda_response['Configuration']['FunctionArn']

        # EventBridge 규칙의 ARN 가져오기
        rule_response = eventbridge_client.describe_rule(Name=eventbridge_rule_name)
        rule_arn = rule_response['Arn']

        # Lambda 권한 추가 (EventBridge가 Lambda를 호출할 수 있도록 설정)
        lambda_client.add_permission(
            FunctionName=lambda_function_name,
            StatementId=f"{eventbridge_rule_name}-InvokeLambda",
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=rule_arn
        )
        print(f"Permission added to Lambda for EventBridge rule: {eventbridge_rule_name}")

        # EventBridge 규칙에 Lambda를 대상(Target)으로 추가
        eventbridge_client.put_targets(
            Rule=eventbridge_rule_name,
            Targets=[
                {
                    'Id': "DetectUnauthorizedAccessTarget",
                    'Arn': lambda_function_arn
                }
            ]
        )
        print(f"EventBridge rule '{eventbridge_rule_name}' successfully linked to Lambda function '{lambda_function_name}'")

    except Exception as e:
        print(f"Error adding EventBridge trigger to Lambda: {e}")

# 실행
add_eventbridge_trigger_to_lambda()
