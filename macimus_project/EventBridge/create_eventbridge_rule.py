import boto3
import json
import zipfile
import os

# AWS 클라이언트 생성
events_client = boto3.client('events', region_name='ap-northeast-2')
macie_client = boto3.client('macie2')
lambda_client = boto3.client('lambda')

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

def create_lambda_zip():
    """Lambda 함수 코드를 포함한 ZIP 파일 생성"""
    try:
        # Lambda 함수 코드 작성
        with open("lambda_function.py", "w") as f:
            f.write('''
import boto3

macie_client = boto3.client('macie2')

def lambda_handler(event, context):
    try:
        # EventBridge 이벤트에서 Job ID 추출
        job_id = event['detail']['jobId']
        print(f"Triggered by Job ID: {job_id}")
        
        # Macie 탐지 결과 가져오기
        findings = macie_client.list_findings()
        finding_ids = findings.get("findingIds", [])
        
        if not finding_ids:
            print("No findings detected.")
            return {"message": "No findings detected"}
        
        # 탐지된 결과 가져오기
        response = macie_client.get_findings(findingIds=finding_ids)
        sensitive_results = response.get('findings', [])
        
        # 결과를 분석하거나 저장
        for finding in sensitive_results:
            print(f"Finding ID: {finding['id']}")
            print(f"Severity: {finding['severity']['description']}")
            print(f"Sensitive Data: {finding.get('classificationDetails', {}).get('result', {}).get('sensitiveData', [])}")
        
        return {"message": "Findings processed successfully"}
    
    except Exception as e:
        print(f"Error processing Macie findings: {e}")
        return {"error": str(e)}
            ''')

        # ZIP 파일 생성
        with zipfile.ZipFile("lambda_function.zip", "w") as zipf:
            zipf.write("lambda_function.py")
        print("Lambda ZIP file created: lambda_function.zip")
    except Exception as e:
        print(f"Error creating Lambda ZIP file: {e}")

def create_lambda_function():
    """Lambda 함수 생성"""
    try:
        # Lambda ZIP 파일 생성
        create_lambda_zip()

        # Lambda 함수 생성
        response = lambda_client.create_function(
            FunctionName="MacieProcessingFunction",
            Runtime="python3.8",
            Role="<ROLE_ARN>",  # Lambda 실행 역할 ARN
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": open("lambda_function.zip", "rb").read()},
            Description="Lambda to process Macie findings.",
            Timeout=15,
            MemorySize=128,
            Publish=True
        )
        print(f"Lambda function created: {response['FunctionArn']}")
        return response['FunctionArn']
    except Exception as e:
        print(f"Error creating Lambda function: {e}")
        return None
    finally:
        # 임시 파일 삭제
        if os.path.exists("lambda_function.py"):
            os.remove("lambda_function.py")
        if os.path.exists("lambda_function.zip"):
            os.remove("lambda_function.zip")

def setup_macie_event_trigger():
    """Macie 이벤트 트리거 설정"""
    # 1. EventBridge 규칙 생성
    rule_arn = create_eventbridge_rule()
    if not rule_arn:
        print("Failed to create EventBridge rule.")
        return

    # 2. Lambda 함수 생성
    lambda_arn = create_lambda_function()
    if not lambda_arn:
        print("Failed to create Lambda function.")
        return

    # 3. EventBridge와 Lambda 연결
    add_lambda_target_to_eventbridge(rule_arn, lambda_arn)
    add_permission_to_lambda("MacieProcessingFunction")

    print("Macie event trigger setup complete.")

# 실행
setup_macie_event_trigger()
