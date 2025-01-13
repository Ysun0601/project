import boto3
import json
import zipfile
import os
import time

# AWS 클라이언트 생성
iam_client = boto3.client('iam')
lambda_client = boto3.client('lambda')
events_client = boto3.client('events', region_name='ap-northeast-2')
sns_client = boto3.client('sns', region_name='ap-northeast-2')

def create_iam_role():
    """IAM 역할 생성 및 정책 연결"""
    try:
        role_name = "LambdaMacieExecutionRole"
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            Description="IAM role for Lambda to process Macie findings"
        )
        role_arn = response['Role']['Arn']
        print(f"IAM Role created: {role_arn}")

        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
        print("Attached AWSLambdaBasicExecutionRole policy.")

        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonMacieFullAccess"
        )
        print("Attached AmazonMacieFullAccess policy.")

        return role_arn
    except Exception as e:
        print(f"Error creating IAM role: {e}")
        return None

def create_sns_topic(topic_name):
    """SNS 주제를 생성합니다."""
    try:
        response = sns_client.create_topic(Name=topic_name)
        topic_arn = response['TopicArn']
        print(f"SNS topic created: {topic_arn}")
        return topic_arn
    except Exception as e:
        print(f"Error creating SNS topic: {e}")
        return None

def subscribe_to_topic(topic_arn, protocol, endpoint):
    """SNS 주제에 구독자를 추가합니다."""
    try:
        response = sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol=protocol,
            Endpoint=endpoint
        )
        print(f"SNS subscription added: {response['SubscriptionArn']}")
        return response['SubscriptionArn']
    except Exception as e:
        print(f"Error adding subscription to SNS topic: {e}")
        return None

def create_lambda_zip():
    """Lambda 함수 코드를 포함한 ZIP 파일 생성"""
    try:
        with open("lambda_function.py", "w") as f:
            f.write('''
import boto3
import os

sns_client = boto3.client('sns', region_name='ap-northeast-2')

def lambda_handler(event, context):
    try:
        job_id = event['detail']['jobId']
        print(f"Triggered by Job ID: {job_id}")
        
        macie_client = boto3.client('macie2')
        findings = macie_client.list_findings()
        finding_ids = findings.get("findingIds", [])
        
        if not finding_ids:
            sns_client.publish(
                TopicArn=os.environ['SNS_TOPIC_ARN'],
                Subject="Macie 탐지 결과 알림",
                Message="No sensitive data detected in the recent Macie job."
            )
            return {"message": "No findings detected"}
        
        response = macie_client.get_findings(findingIds=finding_ids)
        sensitive_results = response.get('findings', [])
        
        message = "Macie 탐지 결과:\n"
        for finding in sensitive_results:
            message += (
                f"- Finding ID: {finding['id']}\n"
                f"  Severity: {finding['severity']['description']}\n"
                f"  Sensitive Data: {finding.get('classificationDetails', {}).get('result', {}).get('sensitiveData', [])}\n"
            )
        
        sns_client.publish(
            TopicArn=os.environ['SNS_TOPIC_ARN'],
            Subject="Macie 탐지 결과 알림",
            Message=message
        )
        
        return {"message": "Findings processed and notification sent"}
    except Exception as e:
        return {"error": str(e)}
            ''')
        with zipfile.ZipFile("lambda_function.zip", "w") as zipf:
            zipf.write("lambda_function.py")
        print("Lambda ZIP file created: lambda_function.zip")
    except Exception as e:
        print(f"Error creating Lambda ZIP file: {e}")

def create_lambda_function(role_arn, sns_topic_arn):
    """Lambda 함수 생성"""
    try:
        create_lambda_zip()
        print("Waiting for IAM role to propagate...")
        time.sleep(10)
        response = lambda_client.create_function(
            FunctionName="MacieProcessingFunction",
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": open("lambda_function.zip", "rb").read()},
            Description="Lambda to process Macie findings and send notifications.",
            Timeout=15,
            MemorySize=128,
            Publish=True,
            Environment={
                'Variables': {
                    'SNS_TOPIC_ARN': sns_topic_arn
                }
            }
        )
        print(f"Lambda function created: {response['FunctionArn']}")
        return response['FunctionArn']
    except Exception as e:
        print(f"Error creating Lambda function: {e}")
        return None
    finally:
        if os.path.exists("lambda_function.py"):
            os.remove("lambda_function.py")
        if os.path.exists("lambda_function.zip"):
            os.remove("lambda_function.zip")

def create_eventbridge_rule():
    """EventBridge 규칙 생성"""
    try:
        rule_name = "MacieClassificationJobCompletedRule"
        response = events_client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps({
                "source": ["aws.macie2"],
                "detail-type": ["Macie Classification Job State Change"],
                "detail": {
                    "jobStatus": ["COMPLETE"]
                }
            }),
            Description="Rule to trigger on Macie Classification Job completion",
            State="ENABLED"
        )
        print(f"EventBridge rule created: {response['RuleArn']}")
        return response['RuleArn']
    except Exception as e:
        print(f"Error creating EventBridge rule: {e}")
        return None

def add_lambda_target_to_eventbridge(rule_arn, lambda_arn):
    """EventBridge 규칙에 Lambda 대상 추가"""
    try:
        response = events_client.put_targets(
            Rule="MacieClassificationJobCompletedRule",
            Targets=[
                {
                    "Id": "1",
                    "Arn": lambda_arn
                }
            ]
        )
        print("Lambda target added to EventBridge rule.")
        return response
    except Exception as e:
        print(f"Error adding Lambda target: {e}")
        return None

def add_permission_to_lambda(lambda_name):
    """Lambda 함수에 EventBridge 호출 권한 부여"""
    try:
        response = lambda_client.add_permission(
            FunctionName=lambda_name,
            StatementId="AllowEventBridgeInvoke",
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=f"arn:aws:events:{boto3.Session().region_name}:{boto3.client('sts').get_caller_identity()['Account']}:rule/MacieClassificationJobCompletedRule"
        )
        print("Permission added to Lambda for EventBridge invocation.")
        return response
    except Exception as e:
        print(f"Error adding permission to Lambda: {e}")
        return None

def setup_macie_event_trigger():
    """IAM 역할 생성부터 Macie 트리거 및 SNS 설정까지"""
    role_arn = create_iam_role()
    if not role_arn:
        print("Failed to create IAM role.")
        return

    sns_topic_arn = create_sns_topic("SensitiveDataAlert")
    if not sns_topic_arn:
        print("Failed to create SNS topic.")
        return

    subscribe_to_topic(sns_topic_arn, "email", "studyer123@gmail.com")

    lambda_arn = create_lambda_function(role_arn, sns_topic_arn)
    if not lambda_arn:
        print("Failed to create Lambda function.")
        return

    rule_arn = create_eventbridge_rule()
    if not rule_arn:
        print("Failed to create EventBridge rule.")
        return

    add_lambda_target_to_eventbridge(rule_arn, lambda_arn)
    add_permission_to_lambda("MacieProcessingFunction")

    print("Macie event trigger with SNS notification setup complete.")

# 실행
setup_macie_event_trigger()
