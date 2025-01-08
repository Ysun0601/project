import boto3

s3_client = boto3.client('s3')
bucket_name = "macimus-data"
response = s3_client.list_objects_v2(Bucket=bucket_name)

if 'Contents' in response:
    for obj in response['Contents']:
        print(f"File: {obj['Key']}, Size: {obj['Size']} bytes")
