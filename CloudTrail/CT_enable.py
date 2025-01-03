# CloudTrail 활성화
import boto3

def enable_cloudtrail(trail_name, bucket_name):
    """
    CloudTrail 활성화 및 S3 로그 저장 설정
    :param trail_name: 생성할 CloudTrail 이름
    :param bucket_name: S3 버킷 이름 (로그 저장 위치)
    """
    cloudtrail_client = boto3.client('cloudtrail')

    try:
        # CloudTrail 생성
        response = cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=True,  # 다중 리전 로그 기록
            IncludeGlobalServiceEvents=True,  # 글로벌 서비스 로그 기록
        )
        print(f"CloudTrail '{trail_name}' created successfully.")
        
        # CloudTrail 활성화
        cloudtrail_client.start_logging(Name=trail_name)
        print(f"CloudTrail '{trail_name}' logging started.")
    except Exception as e:
        print(f"Error enabling CloudTrail: {str(e)}")

if __name__ == "__main__":
    trail_name = "MyCloudTrail"
    bucket_name = "team4-ct-exam1"  # S3 버킷 이름 입력
    enable_cloudtrail(trail_name, bucket_name)
