import boto3
from botocore.exceptions import ClientError

def download_file_from_s3(bucket_name, object_name, local_file_name):
    """
    Download a file from an S3 bucket.
    """
    s3_client = boto3.client('s3')
    try:
        s3_client.download_file(bucket_name, object_name, local_file_name)
        print(f"File '{object_name}' downloaded from bucket '{bucket_name}' to '{local_file_name}'.")

        # 확인: 다운로드한 파일 내용 출력
        with open(local_file_name, "r") as file:
            print("Downloaded file content:")
            print(file.read())

        return True
    except ClientError as e:
        print(f"Error: {e}")
        return False
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        return False

# Main execution
if __name__ == "__main__":
    bucket_name = "team4-exam"  # S3 버킷 이름
    object_name = "user_data.csv"  # S3에 저장된 파일의 키
    local_file_name = "downloaded_user_data.csv"  # 로컬에 저장할 파일 이름

    # 파일 다운로드 함수 호출
    download_file_from_s3(bucket_name, object_name, local_file_name)
