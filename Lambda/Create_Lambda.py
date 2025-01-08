import boto3

def create_lambda_function(function_name, role_arn, handler, runtime, zip_file_path):
    """
    Lambda 함수를 생성합니다.
    :param function_name: Lambda 함수 이름
    :param role_arn: Lambda 실행 역할의 ARN
    :param handler: Lambda 핸들러 (예: 파일명.핸들러명)
    :param runtime: Lambda 실행 환경 (예: 'python3.9')
    :param zip_file_path: 배포 패키지(.zip) 파일 경로
    """
    lambda_client = boto3.client('lambda', region_name='ap-northeast-2')

    try:
        with open(zip_file_path, 'rb') as zip_file:
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler,
                Code={'ZipFile': zip_file.read()},
                Description='Handles sensitive data access alerts',
                Timeout=10,  # 초 단위로 설정
                MemorySize=128,  # 메모리 크기 설정 (MB)
            )
        print(f"Lambda function '{function_name}' created successfully.")
        return response['FunctionArn']
    except Exception as e:
        print(f"Error creating Lambda function: {e}")

# 실행
if __name__ == "__main__":
    function_name = "SensitiveDataAlertHandler"
    role_arn = "arn:aws:iam::423623825149:role/LambdaExecutionRole"  # Lambda 실행 역할 ARN
    handler = "lambda_function.lambda_handler"  # 핸들러 함수
    runtime = "python3.11"  # 런타임 환경
    zip_file_path = "./Lambda_Handler.zip"  # 배포 패키지 경로 (.zip 파일)

    create_lambda_function(function_name, role_arn, handler, runtime, zip_file_path)
