import boto3
import json

# AWS IAM 클라이언트 생성
iam_client = boto3.client('iam')

# 사용자 생성 함수
def create_user(user_name):
    try:
        response = iam_client.create_user(UserName=user_name)
        print(f"User '{user_name}' created successfully.")
        return response['User']['UserName']
    except Exception as e:
        print(f"Error creating user '{user_name}': {str(e)}")
        return None

# 정책 생성 함수
def create_policy(policy_name, policy_document):
    try:
        # 고유한 정책 이름 생성
        from datetime import datetime
        policy_name = f"{policy_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        print(f"Policy '{policy_name}' created successfully.")
        return response['Policy']['Arn']
    except Exception as e:
        print(f"Error creating policy '{policy_name}': {str(e)}")
        return None


# 사용자에 정책 연결 함수
def attach_policy_to_user(user_name, policy_arn):
    try:
        iam_client.attach_user_policy(
            UserName=user_name,
            PolicyArn=policy_arn
        )
        print(f"Policy '{policy_arn}' attached to user '{user_name}'.")
    except Exception as e:
        print(f"Error attaching policy to user '{user_name}': {str(e)}")

# 액세스 키 생성 함수
def create_access_key(user_name):
    try:
        response = iam_client.create_access_key(UserName=user_name)
        access_key = response['AccessKey']
        print(f"Access key created for user '{user_name}'.")
        return {
            "AccessKeyId": access_key['AccessKeyId'],
            "SecretAccessKey": access_key['SecretAccessKey']
        }
    except Exception as e:
        print(f"Error creating access key for user '{user_name}': {str(e)}")
        return None

# 액세스 키 정보 저장 함수
def save_keys_to_file(user_name, access_key):
    file_name = f"{user_name}_access_key.json"
    try:
        with open(file_name, 'w') as f:
            json.dump(access_key, f, indent=4)
        print(f"Access key for user '{user_name}' saved to '{file_name}'.")
    except Exception as e:
        print(f"Error saving access key for user '{user_name}': {str(e)}")

# 주요 실행 로직
if __name__ == "__main__":
    # 사용자 및 정책 정의
    users = [
        {"name": "MacieUser", "policy_name": "MaciePolicy", "permissions": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    
                    "Action": [
                        "macie2:CreateClassificationJob",
                        "macie2:GetFindings",
                        "macie2:ListFindings",
                        "s3:ListBucket",
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": "*"
                }
            ]
        }},
        {"name": "CloudTrailUser", "policy_name": "CloudTrailPolicy", "permissions": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["cloudtrail:LookupEvents", "cloudtrail:DescribeTrails", "s3:GetObject"],
                    "Resource": "*"
                }
            ]
        }},
        {"name": "LambdaUser", "policy_name": "LambdaPolicy", "permissions": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["lambda:InvokeFunction", "s3:PutObject", "s3:GetObject", "iam:PassRole"],
                    "Resource": "*"
                }
            ]
        }},
        {"name": "ReportUser", "policy_name": "ReportPolicy", "permissions": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:GetObject", "ses:SendEmail", "sns:Publish"],
                    "Resource": "*"
                }
            ]
        }},
    ]

    # 사용자 생성 및 정책 연결, 액세스 키 생성
    for user in users:
        user_name = user["name"]
        policy_name = user["policy_name"]
        policy_document = user["permissions"]

        # 사용자 생성
        created_user = create_user(user_name)

        if created_user:
            # 정책 생성
            policy_arn = create_policy(policy_name, policy_document)
            if policy_arn:
                # 사용자에 정책 연결
                attach_policy_to_user(created_user, policy_arn)

            # 액세스 키 생성
            access_key = create_access_key(created_user)
            if access_key:
                # 액세스 키 저장
                save_keys_to_file(created_user, access_key)