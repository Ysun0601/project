import boto3
import zipfile
import os

# Lambda 클라이언트 초기화
lambda_client = boto3.client('lambda')

def create_lambda_function():
    """
    Lambda 함수 생성
    """
    # Lambda 실행 역할 ARN (사전에 생성된 역할 사용)
    role_arn = "arn:aws:iam::423623825149:role/LambdaExecutionRole"  # 적합한 역할 ARN으로 수정

    # Lambda 함수 코드 파일 및 ZIP 경로
    lambda_file = "lambda_function.py"
    zip_file = "lambda_function.zip"

    # Lambda 코드 작성
    with open(lambda_file, "w") as f:
        f.write('''  # [수정됨]: 파일 작성에 멀티라인 문자열 사용
import boto3

sns_client = boto3.client('sns')
sns_topic_arn = "arn:aws:sns:ap-northeast-2:423623825149:UnauthorizedAccessAlert"

AUTHORIZED_USERS = [
    "arn:aws:iam::423623825149:user/YOO",
    "arn:aws:iam::423623825149:user/Park",
    "arn:aws:iam::423623825149:user/Jung"
]

# 한국 IP 대역 정의
KOREA_IP_RANGES = [
    "121.128.0.0/11"  # 예시 대역
]

def is_ip_in_korea(ip):
    for cidr in KOREA_IP_RANGES:
        if ip_address(ip) in ip_network(cidr):
            return True
    return False

def lambda_handler(event, context):
    """

    """
    #Lambda 핸들러: 모든 조건을 분석하고 통합된 경고 메시지 생성
    try:
        detail = event['detail']
        source_ip = detail.get('sourceIPAddress', 'Unknown IP')
        user_arn = detail.get('userIdentity', {}).get('arn', 'UnknownUser')
        event_name = detail.get('eventName', 'Unknown Event')
        bucket_name = detail.get('requestParameters', {}).get('bucketName', 'UnknownBucket')
        object_key = detail.get('requestParameters', {}).get('key', 'UnknownObject')

        # 분석 결과 초기화
        reasons = []  # 경고 사유를 담을 리스트

        # 1. 허용되지 않은 IP 감지
        if not is_ip_in_korea(source_ip):
            reasons.append("- Unauthorized IP detected")

        # 2. 권한 없는 사용자 감지
        if user_arn not in AUTHORIZED_USERS:
            reasons.append("- Unauthorized user detected")

        # 3. 비인가된 시스템 자원 접근 감지
        if event_name in ["PutObject", "DeleteObject"] and user_arn not in AUTHORIZED_USERS:
            reasons.append("- Unauthorized system resource access detected")


        # 경고 메시지 생성
        if reasons:  # 하나 이상의 조건이 충족된 경우
            reason_text = "\\n".join(reasons)  # 사유를 줄바꿈으로 구분하여 연결
            message = (
                f"Warning:\\n"
                f"{reason_text}\\n"
                f"Source IP: {source_ip}\\n"
                f"Event: {event_name}\\n"
                f"Bucket: {bucket_name}\\n"
                f"Object: {object_key}\\n"
            )
            try:
                sns_client.publish(
                    TopicArn=sns_topic_arn,
                    Subject="Unauthorized Access Detected",
                    Message=message
                )
                print(f"Alert sent: {message}")
            except Exception as sns_error:
                print(f"Error sending SNS alert: {sns_error}")
        else:
            print("No unauthorized access detected.")

        return {"status": "success"}
    except Exception as e:
        print(f"Error processing event: {e}")
        return {"status": "error", "message": str(e)}

        ''')

    # ZIP 파일 생성
    with zipfile.ZipFile(zip_file, 'w') as z:
        z.write(lambda_file)

    # Lambda 함수 생성
    try:
        with open(zip_file, 'rb') as f:
            response = lambda_client.create_function(
                FunctionName="DetectUnauthorizedS3Access",
                Runtime="python3.9",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={
                    "ZipFile": f.read()
                },
                Description="Lambda function to detect unauthorized S3 access and send alerts via SNS",
                Timeout=15,
                MemorySize=128,
                Publish=True
            )
        print(f"Lambda function created successfully: {response['FunctionArn']}")
    except Exception as e:
        print(f"Error creating Lambda function: {e}")

    # 파일 정리
    os.remove(lambda_file)
    os.remove(zip_file)

# 실행
create_lambda_function()
