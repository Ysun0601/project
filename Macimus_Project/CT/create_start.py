import boto3

# CloudTrail 클라이언트 생성
cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')

# CloudTrail 생성 함수
def create_cloudtrail(trail_name, bucket_name):
    try:
        response = cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=True
        )
        print(f"CloudTrail {trail_name} created successfully.")
        return response
    except Exception as e:
        print(f"Error creating CloudTrail: {e}")

# CloudTrail 로깅 시작 함수
def start_cloudtrail_logging(trail_name):
    try:
        cloudtrail_client.start_logging(Name=trail_name)
        print(f"CloudTrail {trail_name} logging started.")
    except Exception as e:
        print(f"Error starting CloudTrail logging: {e}")

# CloudTrail 이름 및 로그 저장 버킷 이름
trail_name = "n-team4-m-new-trail"
bucket_name = "n-macimus-cloudtrail-logs"

# 실행
create_cloudtrail(trail_name, bucket_name)
start_cloudtrail_logging(trail_name)
