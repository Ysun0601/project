import boto3
import json
from botocore.exceptions import ClientError

def attach_policy_to_user(user_name, policy_name, policy_document):
    """
    IAM 사용자에 JSON 형식의 인라인 정책 추가.

    Parameters:
        user_name (str): 정책을 추가할 IAM 사용자 이름.
        policy_name (str): 추가할 인라인 정책의 이름.
        policy_document (dict): 정책의 JSON 형식 내용.
    """
    iam_client = boto3.client('iam')

    try:
        # JSON 형식의 정책을 IAM 사용자에 추가
        response = iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        print(f"Policy '{policy_name}' successfully added to user '{user_name}'.")
    except ClientError as e:
        print(f"Error adding policy to user '{user_name}': {e}")

# 실행
if __name__ == "__main__":
    # 사용자 이름과 정책 이름 설정
    user_name = "CloudTrailUser"  # IAM 사용자 이름
    policy_name = "CloudTrailExtendedPolicy"  # 사용자 정의 정책 이름

    # 중복된 권한을 제외한 추가 권한 JSON 정책
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "cloudtrail:CreateTrail",
                    "cloudtrail:StartLogging",
                    "cloudtrail:PutEventSelectors",
                    "s3:PutBucketPolicy",
                    "s3:GetBucketAcl",
                    "s3:PutObject"
                ],
                "Resource": "*"
            }
        ]
    }

    # IAM 사용자에 정책 추가
    attach_policy_to_user(user_name, policy_name, policy_document)
