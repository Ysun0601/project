import boto3
import json

def apply_bucket_policy(bucket_name):
    s3_client = boto3.client('s3')
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/423623825149/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            },
            {
                "Sid": "AllowBucketRead",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}"
            }
        ]
    }
    try:
        response = s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        print(f"Bucket policy applied to '{bucket_name}'.")
    except Exception as e:
        print(f"Error applying bucket policy: {e}")

# 실행
if __name__ == "__main__":
    bucket_name = "macimus4-ctrail-log-bucket"
    apply_bucket_policy(bucket_name)
