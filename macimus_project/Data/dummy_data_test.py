import boto3
import json
import random
import string
from faker import Faker
from datetime import datetime
from botocore.exceptions import ClientError
import uuid

# Faker 인스턴스 생성 (한국 로케일 설정)
fake = Faker("ko_KR")

# S3 클라이언트 생성
s3_client = boto3.client('s3', region_name="ap-northeast-2")

# 민감 데이터 생성 함수
def generate_sensitive_data(num_records=100):
    def generate_nickname():
        start = 0xAC00
        end = 0xD7A3
        return ''.join(chr(random.randint(start, end)) for _ in range(5))
    
    def generate_email():
        random_string = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))
        return f"{random_string}@example.com"
    
    def generate_phone_number():
        return f"010-{''.join(random.choices(string.digits, k=4))}-{''.join(random.choices(string.digits, k=4))}"
    
    def generate_address():
        return ''.join(random.choices(string.digits, k=5))
    
    def generate_device():
        devices = ["갤럭시24", "갤럭시25", "아이폰16", "아이폰15"]
        return random.choice(devices)
    
    def generate_cvv():
    # 3~4자리 숫자 생성
        cvv_length = random.choice([3, 4])  # CVV 길이를 3 또는 4로 선택
        cvv_numbers = ''.join(random.choices("0123456789", k=cvv_length))
    # 숫자마다 ':' 삽입
        return ':'.join(cvv_numbers)

    data = []
    for _ in range(num_records):
        user_id = str(uuid.uuid4())  # 고유 user_id 생성
        record = {
            "user_id": user_id,
            "nickname": generate_nickname(),
            "name": fake.name(),
            "email": generate_email(),
            "phone_number": generate_phone_number(),
            "address": generate_address(),
            "credit_card": {
                "card_number": fake.credit_card_number(card_type='visa'),
                "expiry_date": fake.credit_card_expire(start=2025, end=2030),
                "cvv": generate_cvv()
            },
            "login_history": [
                {
                    "timestamp": fake.date_time_this_year().isoformat(),
                    "ip_address": fake.ipv4_private(),
                    "devices": generate_device()
                }
                for _ in range(3)
            ]
        }
        data.append(record)
    return data

# JSON 데이터 분리 함수
def split_data(data):
    low_severity_data = [
        {"user_id": record["user_id"], "nickname": record["nickname"]}
        for record in data
    ]
    medium_severity_data = [
        {
            "user_id": record["user_id"],
            "name": record["name"],
            "email": record["email"],
            "phone_number": record["phone_number"],
            "address": record["address"],
            "login_history": [
                {"timestamp": login["timestamp"], "devices": login["devices"]}
                for login in record["login_history"]
            ]
        }
        for record in data
    ]
    high_severity_data = [
        {
            "user_id": record["user_id"],
            "credit_card": {
                "card_number": record["credit_card"]["card_number"],
                "expiry_date": record["credit_card"]["expiry_date"],
                "cvv": record["credit_card"]["cvv"]
            },
            "login_history": [
                {"ip_address": login["ip_address"]}
                for login in record["login_history"]
            ]
        }
        for record in data
    ]
    return low_severity_data, medium_severity_data, high_severity_data

# JSON 파일 업로드 함수
def upload_data_to_s3(bucket_name, file_name, data):
    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(data, indent=2, ensure_ascii=False),
            ContentType='application/json'
        )
        print(f"File '{file_name}' uploaded successfully to bucket '{bucket_name}'.")
    except ClientError as e:
        print(f"Error uploading file: {e}")

# 데이터 생성
sensitive_data = generate_sensitive_data(num_records=100)

# 데이터 분리
low_severity_data, medium_severity_data, high_severity_data = split_data(sensitive_data)

# S3 버킷 이름
bucket_name = "n-macimus-sensitive-data"

# JSON 파일 업로드
upload_data_to_s3(bucket_name, "low-severity.json", low_severity_data)
upload_data_to_s3(bucket_name, "medium-severity.json", medium_severity_data)
upload_data_to_s3(bucket_name, "high-severity.json", high_severity_data)
