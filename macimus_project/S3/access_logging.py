import boto3

def enable_server_access_logging(target_bucket_name, log_bucket_name, log_prefix):
    s3_client = boto3.client('s3', region_name='ap-northeast-2')
    try:
        # 서버 액세스 로깅 활성화
        s3_client.put_bucket_logging(
            Bucket=target_bucket_name,
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': log_bucket_name,
                    'TargetPrefix': log_prefix
                }
            }
        )
        print(f"Server access logging enabled for bucket: {target_bucket_name}")
    except Exception as e:
        print(f"Error enabling server access logging: {e}")

if __name__ == "__main__":
    target_bucket_name = "n-macimus-sensitive-data"  # 요청을 추적할 S3 버킷
    log_bucket_name = "n-macimus-cloudtrail-logs"  # 로그를 저장할 S3 버킷
    log_prefix = "server-access-logs/"  # 로그 파일의 저장 경로

    enable_server_access_logging(target_bucket_name, log_bucket_name, log_prefix)
