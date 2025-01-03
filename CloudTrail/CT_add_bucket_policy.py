# CloudTrail을 위한 버킷 정책 추가
import boto3
import json

def add_bucket_policy(bucket_name):
    s3_client = boto3.client('s3')
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}"
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                }
            }
        ]
    }
    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print(f"Bucket policy added to {bucket_name}.")
    except Exception as e:
        print(f"Error adding bucket policy: {str(e)}")

if __name__ == "__main__":
    bucket_name = "team4-ct-exam1"
    add_bucket_policy(bucket_name)
