import boto3
import json
from faker import Faker

# AWS 클라이언트 초기화
s3_client = boto3.client('s3')
macie_client = boto3.client('macie2', region_name='ap-northeast-2')

# S3 버킷 이름 설정
bucket_name = "test-test-1234"

# Faker 초기화 (한국어 로케일 설정)
faker = Faker("ko_KR")

# 신용카드 번호 형식 변환 함수
def generate_formatted_credit_card():
    raw_credit_card = faker.credit_card_number(card_type=None).ljust(16, '0')
    return '-'.join([raw_credit_card[i:i+4] for i in range(0, 16, 4)])

# 민감 데이터 생성 함수
def generate_dummy_data_json(num_records=100):
    data = []
    for _ in range(num_records):
        name = faker.name()
        email = faker.email()
        ssn = faker.ssn()
        ccn = generate_formatted_credit_card()  # 형식화된 신용카드 번호 생성

        data.append({
            "Name": name,
            "Email": email,
            "SSN": ssn,
            "CCN": ccn  # 키 이름 변경
        })
    return data

# 데이터를 S3에 업로드하는 함수
def upload_dummy_data(num_users=100):
    try:
        for i in range(1, num_users + 1):
            user_data = generate_dummy_data_json(num_records=1)[0]
            user_id = f"user_{i:03d}"

            high_sensitive_data = {
                "ssn": user_data["SSN"],
                "ccn": user_data["CCN"]  # 키 이름 변경
            }
            medium_sensitive_data = {
                "name": user_data["Name"],
                "email": user_data["Email"]
            }

            # 고민감 데이터 업로드
            s3_client.put_object(
                Bucket=bucket_name,
                Key=f"{user_id}_high_sensitive_data.json",
                Body=json.dumps(high_sensitive_data, ensure_ascii=False),
                ContentType="application/json"
            )

            # 중간 민감 데이터 업로드
            s3_client.put_object(
                Bucket=bucket_name,
                Key=f"{user_id}_medium_sensitive_data.json",
                Body=json.dumps(medium_sensitive_data, ensure_ascii=False),
                ContentType="application/json"
            )
    except Exception as e:
        print(f"Error uploading dummy data: {e}")

if __name__ == "__main__":
    # 1. 데이터 업로드
    upload_dummy_data(num_users=100)
    