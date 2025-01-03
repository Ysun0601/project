# 로그 다운로드 
import boto3

def download_cloudtrail_logs(bucket_name, prefix, download_path):
    """
    S3에서 CloudTrail 로그 파일 다운로드
    :param bucket_name: CloudTrail 로그가 저장된 S3 버킷 이름
    :param prefix: 로그 파일 경로의 S3 키(prefix)
    :param download_path: 로컬에 저장할 디렉토리 경로
    """
    s3_client = boto3.client('s3')
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if 'Contents' in response:
            for obj in response['Contents']:
                file_name = obj['Key'].split('/')[-1]
                s3_client.download_file(bucket_name, obj['Key'], f"{download_path}/{file_name}")
                print(f"Downloaded: {file_name}")
        else:
            print("No logs found.")
    except Exception as e:
        print(f"Error downloading CloudTrail logs: {str(e)}")
