import boto3
import json

def create_lambda_execution_role(role_name):
    iam_client = boto3.client('iam')

    # Trust Policy: Lambda 서비스가 역할을 사용할 수 있도록 허용
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # IAM 역할 생성
    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        print(f"Role {role_name} created successfully.")
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Role {role_name} already exists. Skipping creation.")
        response = iam_client.get_role(RoleName=role_name)

    # Lambda 실행 권한 추가
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:PutObject"
                ],
                "Resource": [
                    "arn:aws:s3:::macimus-data",
                    "arn:aws:s3:::macimus-data/*",
                    "arn:aws:s3:::macimus-cloudtrail-bucket-logs",
                    "arn:aws:s3:::macimus-cloudtrail-bucket-logs/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": "sns:Publish",
                "Resource": "arn:aws:sns:ap-northeast-2:423623825149:SensitiveDataAlertTopic"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "macie2:GetFindings",
                    "macie2:ListFindings",
                    "macie2:CreateClassificationJob"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "cloudtrail:LookupEvents",
                    "cloudtrail:GetEventSelectors",
                    "cloudtrail:ListTrails"
                ],
                "Resource": "*"
            }
        ]
    }

    try:
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="LambdaExecutionPolicy",
            PolicyDocument=json.dumps(policy_document)
        )
        print(f"Policy attached to role {role_name} successfully.")
    except Exception as e:
        print(f"Error attaching policy to role: {e}")

if __name__ == "__main__":
    create_lambda_execution_role("LambdaExecutionRole")
