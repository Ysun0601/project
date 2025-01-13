import boto3

region = "ap-northeast-2"
bucket_name = "n3-macimus-cloudtrail-logs"

cloudtrail_client = boto3.client('cloudtrail', region_name=region)

def create_cloudtrail(trail_name, bucket_name):
    try:
        cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name
        )
        print(f"CloudTrail '{trail_name}' created successfully.")
    except Exception as e:
        print(f"Error creating CloudTrail: {e}")

def start_cloudtrail_logging(trail_name):
    try:
        cloudtrail_client.start_logging(Name=trail_name)
        print(f"CloudTrail '{trail_name}' logging started successfully.")
    except Exception as e:
        print(f"Error starting CloudTrail logging: {e}")


# 실행
trail_name = "n3-macimus-cloudtrail"
create_cloudtrail(trail_name, bucket_name)
start_cloudtrail_logging(trail_name)
