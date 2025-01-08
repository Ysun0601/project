import boto3

def add_lambda_trigger(rule_name, lambda_function_arn):
    """
    EventBridge 규칙과 Lambda 함수를 연결.
    :param rule_name: EventBridge 규칙 이름
    :param lambda_function_arn: Lambda 함수 ARN
    """
    events_client = boto3.client('events')
    lambda_client = boto3.client('lambda')
    try:
        # EventBridge 규칙의 ARN 가져오기
        rule_response = events_client.describe_rule(Name=rule_name)
        rule_arn = rule_response['Arn']  # Rule ARN 가져오기

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
        print(f"Error adding Lambda trigger: {e}")

# 실행
if __name__ == "__main__":
    add_lambda_trigger(
        rule_name="SensitiveDataAccessAlert",
        lambda_function_arn="arn:aws:lambda:ap-northeast-2:423623825149:function:YourLambdaFunctionName"
    )
