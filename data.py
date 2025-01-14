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

# 민감 데이터 생성 함수
def generate_dummy_data_json(num_records=100):
    data = []
    for _ in range(num_records):
        name = faker.name()
        email = faker.email()
        ssn = faker.ssn()
        credit_card = faker.credit_card_number(card_type=None)
        data.append({
            "Name": name,
            "Email": email,
            "SSN": ssn,
            "CreditCardNumber": credit_card
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
                "credit_card": user_data["CreditCardNumber"]
            }
            medium_sensitive_data = {
                "name": user_data["Name"],
                "email": user_data["Email"]
            }

            s3_client.put_object(
                Bucket=bucket_name,
                Key=f"{user_id}_high_sensitive_data.json",
                Body=json.dumps(high_sensitive_data, ensure_ascii=False),
                ContentType="application/json"
            )

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