import boto3

def create_custom_data_identifier(name, regex, description="Custom Data Identifier", keywords=None):
    """
    사용자 정의 데이터 식별자 생성
    :param name: 사용자 정의 데이터 식별자 이름
    :param regex: 정규 표현식
    :param description: 식별자 설명
    :param keywords: 키워드 리스트 (옵션)
    """
    macie_client = boto3.client('macie2')

    try:
        response = macie_client.create_custom_data_identifier(
            name=name,
            regex=regex,
            description=description,
            keywords=keywords if keywords else []
        )
        print(f"Custom Data Identifier created: {response['id']}")
        return response['id']
    except Exception as e:
        print(f"Error creating custom data identifier: {e}")

# 실행
if __name__ == "__main__":
    # 각 항목에 대한 사용자 정의 데이터 식별자 생성
    identifiers = [
        {"name": "MemberIDIdentifier", "regex": r"\b\d{6}\b", "description": "Matches Member IDs"},
        {"name": "PasswordIdentifier", "regex": r"[a-zA-Z0-9!@#$%^&*]{8,}", "description": "Matches Passwords"},
        {"name": "NameIdentifier", "regex": r"[가-힣]{2,4}", "description": "Matches Korean Names"},
        {"name": "PhoneIdentifier", "regex": r"010-\d{4}-\d{4}", "description": "Matches Korean Phone Numbers"},
        {"name": "EmailIdentifier", "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "description": "Matches Emails"},
        {"name": "SocialLoginIdentifier", "regex": r"google|facebook|kakao|naver", "description": "Matches Social Login Providers"},
        {"name": "DateIdentifier", "regex": r"\d{4}-\d{2}-\d{2}", "description": "Matches Dates"}
    ]

    # 사용자 정의 데이터 식별자 생성
    for identifier in identifiers:
        create_custom_data_identifier(identifier["name"], identifier["regex"], identifier["description"])
