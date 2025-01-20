import boto3
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

region = "ap-northeast-2"
bucket_name = "macimus-logs"
trail_name = "macimus-cloudtrail"

# CloudTrail 클라이언트 초기화
cloudtrail_client = boto3.client('cloudtrail', region_name=region)

def create_cloudtrail(trail_name, bucket_name):
    try:
        # CloudTrail 생성
        cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            EnableLogFileValidation=True  # 로그 무결성 확인 활성화
        )
        logger.info(f"{trail_name}이 성공적으로 생성되었으며, 로그 파일 검증이 활성화되었습니다.")
    except cloudtrail_client.exceptions.TrailAlreadyExistsException:
        logger.warning(f"CloudTrail '{trail_name}' already exists.")
    except Exception as e:
        logger.error(f"Error creating CloudTrail: {e}")

def start_cloudtrail_logging(trail_name):
    try:
        # 로깅 시작
        cloudtrail_client.start_logging(Name=trail_name)
        logger.info(f"{trail_name} 로깅이 성공적으로 시작되었습니다. .")
    except Exception as e:
        logger.error(f"Error starting CloudTrail logging: {e}")

# 실행
create_cloudtrail(trail_name, bucket_name)
start_cloudtrail_logging(trail_name)