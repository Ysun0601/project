import boto3
import json
import random
import string
from faker import Faker
from datetime import date
from botocore.exceptions import ClientError

# Faker 인스턴스 생성 (한국 로케일 설정)
fake = Faker("ko_KR")

# 민감 데이터 생성 함수
def generate_sensitive_data(num_records=100):
    def generate_user_id():
        return ''.join(random.choices(string.ascii_letters + string.digits, k=6))  # 6자리 영문+숫자
    
    def generate_email():
        random_string = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))
        return f"{random_string}@example.com"
    
    def generate_phone_number():
        return f"010-{''.join(random.choices(string.digits, k=4))}-{''.join(random.choices(string.digits, k=4))}"
    
    def generate_address():
        city = fake.city()  # 한국 시 이름
        district = fake.street_name()  # 한국 동 이름
        building_number = ''.join(random.choices(string.digits, k=3))  # 3자리 숫자
        return f"{city}시 {district} {building_number}"
    
    data = []
    for _ in range(num_records):
        record = {
            "user_id": generate_user_id(),
            "name": fake.name(),  # 한국식 이름
            "email": generate_email(),
            "phone_number": generate_phone_number(),
            "address": generate_address(),
            "credit_card": {
                "card_number": fake.credit_card_number(card_type='visa'),  # 카드 번호
                "expiry_date": fake.credit_card_expire(start=2025, end=2030),  # 카드 유효기간 (연도 범위로 수정)
                "cvv": fake.credit_card_security_code()  # 카드 보안 코드
            },
            "login_history": [
                {
                    "timestamp": fake.date_time_this_year().isoformat(),  # ISO 8601 형식의 로그인 시간
                    "ip_address": fake.ipv4_private(),  # 내부 IP
                    "device": fake.user_agent()  # 랜덤 디바이스 정보
                } for _ in range(3)  # 최근 3번의 로그인 기록
            ]
        }
        data.append(record)
    return data

# 데이터 생성
sensitive_data = generate_sensitive_data(num_records=100)

# JSON 파일로 저장 및 S3 업로드 함수
def upload_data_to_s3(bucket_name, file_name, data):
    try:
        s3_client = boto3.client('s3')
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(data, indent=2, ensure_ascii=False),  # ensure_ascii=False로 한글 저장
            ContentType='application/json',
        )
        print(f"File {file_name} uploaded successfully to {bucket_name}.")
    except ClientError as e:
        print(f"Error uploading file: {e}")

# S3 버킷 이름 및 파일 이름
bucket_name = "n-macimus-sensitive-data"
file_name = "sensitive-data-100-krusers.json"

# 업로드 실행
upload_data_to_s3(bucket_name, file_name, sensitive_data)
