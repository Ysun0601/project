import boto3
import json
from faker import Faker
from botocore.exceptions import ClientError

# Faker 인스턴스 생성
fake = Faker()

# 민감 데이터 생성 함수
def generate_sensitive_data(num_records=100):
    data = []
    for _ in range(num_records):
        record = {
            "user_id": fake.uuid4(),
            "name": fake.name(),
            "email": fake.email(),
            "phone_number": fake.phone_number(),
            "address": fake.address(),
            "credit_card": {
                "card_number": fake.credit_card_number(),
                "expiry_date": fake.credit_card_expire(),
                "cvv": fake.credit_card_security_code()
            },
            "login_history": [
                {
                    "timestamp": fake.date_time_this_year().isoformat(),
                    "ip_address": fake.ipv4(),
                    "device": fake.user_agent()
                } for _ in range(3)  # 최근 3번의 로그인 기록
            ]
        }
        data.append(record)
    return data

# 데이터 생성
sensitive_data = generate_sensitive_data(num_records=100)

# JSON 파일로 저장 및 S3 업로드
def upload_data_to_s3(bucket_name, file_name, data):
    try:
        s3_client = boto3.client('s3')
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(data, indent=2),
            ContentType='application/json',

        )
        print(f"File {file_name} uploaded successfully to {bucket_name}.")
    except ClientError as e:
        print(f"Error uploading file: {e}")

# S3 버킷 이름 및 파일 이름
bucket_name = "n1-macimus-sensitive-data"
file_name = "sensitive-data-100-users.json"

# 업로드 실행
upload_data_to_s3(bucket_name, file_name, sensitive_data)




