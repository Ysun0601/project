import boto3
from botocore.exceptions import ClientError

def upload_file_to_s3(file_name, bucket_name, object_name=None):
    """
    Upload a file to an S3 bucket.
    """
    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file using open to ensure file content is read
    s3_client = boto3.client('s3')
    try:
        with open(file_name, "rb") as file_data:
            s3_client.put_object(Bucket=bucket_name, Key=object_name, Body=file_data)
        print(f"File '{file_name}' uploaded to bucket '{bucket_name}' as '{object_name}'.")
    except ClientError as e:
        print(f"Error: {e}")
        return False
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        return False
    return True

# Main execution
if __name__ == "__main__":
    bucket_name = "team4-exam2"  # S3 버킷 이름
    file_name = "user_data.csv"  # 로컬 파일 이름
    object_name = "user_data.csv"  # S3에 저장될 파일 이름

    # 파일 업로드 함수 호출
    upload_file_to_s3(file_name, bucket_name, object_name)
