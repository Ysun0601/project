import boto3

s3_client = boto3.client('s3', region_name='ap-northeast-2')
bucket_name = 'n-macimus-sensitive-data'
object_key = 'test-object.txt'

# 테스트 파일 업로드
with open('test-file.txt', 'w') as file:
    file.write('Test content for CloudTrail logging.')

s3_client.upload_file('test-file.txt', bucket_name, object_key)

# 테스트 파일 다운로드
s3_client.download_file(bucket_name, object_key, 'downloaded-test-file.txt')

# 테스트 파일 삭제
s3_client.delete_object(Bucket=bucket_name, Key=object_key)
