from faker import Faker
import random
import pandas as pd
import string

fake = Faker('ko_KR')
Faker.seed(1)

repeat_count = 10000

# 랜덤 숫자 ID 생성 함수
def generate_random_ids(count, id_range=(100000, 999999)):
    """중복되지 않는 랜덤 ID 생성."""
    return random.sample(range(id_range[0], id_range[1] + 1), count)

# 랜덤 문자열(영문자 + 숫자) 비밀번호 생성 함수
def generate_password(length=10):
    """랜덤 비밀번호 생성 (영문자와 숫자의 조합)."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

member_id = generate_random_ids(repeat_count)
password = [generate_password(10) for _ in range(repeat_count)]
name = [fake.name() for i in range(repeat_count)]
phone = [
    ('010-'+str(random.randint(1, 9999)).zfill(4)
        +'-'+str(random.randint(1, 9999)).zfill(4))
    for i in range(repeat_count)
]
user_status 	= ['active' for i in range(repeat_count)]
email 			= [fake.unique.free_email() for i in range(repeat_count)]
social_login 	= [random.choice(['google','facebook','kakao','naver']) for i in range(repeat_count)]
last_logged_at 	= [fake.date_between(start_date = '-1y', end_date ='today') for i in range(repeat_count)]
created_at 		= [fake.date_between(start_date = '-1y', end_date ='today') for i in range(repeat_count)]

df = pd.DataFrame()
df['member_id'] = member_id
df['password'] = password
df['name'] = name
df['phone'] = phone
df['user_status'] = user_status
df['email'] = email
df['social_login'] = social_login
df['last_logged_at'] = last_logged_at
df['created_at'] = created_at

# 데이터프레임을 딕셔너리 형태로 변환
records = df.to_dict(orient='records')

# 결과 출력 및 저장
print(records)  # 레코드 출력
df.to_csv("dummy_data_random_ids.csv", index=False, encoding='utf-8-sig')
print("Dummy data saved to 'dummy_data_random_ids.csv'")