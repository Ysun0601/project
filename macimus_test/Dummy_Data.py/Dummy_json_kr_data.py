import boto3
import json
import random
import string
from faker import Faker
from datetime import date
from botocore.exceptions import ClientError

# Faker 초기화 (한국어 로케일 설정)
faker = Faker("ko_KR")

# 민감 데이터 생성 함수
def generate_sensitive_data(num_records=1):
    def generate_email():
        random_string = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))
        return f"{random_string}@example.com"
    
    def generate_phone_number():
        return f"010-{''.join(random.choices(string.digits, k=4))}-{''.join(random.choices(string.digits, k=4))}"
    
    def generate_address():
        return ''.join(random.choices(string.digits, k=5))  # 숫자 5자리 주소 생성

    def generate_formatted_ccn():
        raw_credit_card = faker.credit_card_number(card_type=None).ljust(16, '0')
        return '-'.join([raw_credit_card[i:i+4] for i in range(0, 16, 4)])

    def generate_bank_account():
        # 계좌번호 형식: 000-00-000000
        return f"{''.join(random.choices(string.digits, k=3))}-" \
               f"{''.join(random.choices(string.digits, k=2))}-" \
               f"{''.join(random.choices(string.digits, k=6))}"

    data = []
    for _ in range(num_records):
        record = {
            "name": faker.name(),  # 한국식 이름
            "email": generate_email(),
            "phone_number": generate_phone_number(),
            "address": generate_address(),  # 도로명 느낌의 숫자 5자리
            "ssn": faker.ssn(),  # 주민등록번호
            "ccn": generate_formatted_ccn(),  # 신용카드 번호 (ccn)
            "bank_account": generate_bank_account()  # 계좌번호
        }
        data.append(record)
    return data

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

# 데이터 생성
sensitive_data = generate_sensitive_data(num_records=100)

# S3 버킷 이름 및 파일 이름
bucket_name = "macimus-user-data-2"
file_name = "Test(높음).json"

# 업로드 실행
upload_data_to_s3(bucket_name, file_name, sensitive_data)
