import boto3
import json

def create_iam_role_for_cloudtrail(role_name, policy_name):
    iam_client = boto3.client('iam')

    # 신뢰 정책 설정
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }

    # 권한 정책 설정
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:ap-northeast-2:423623825149:log-group:/aws/cloudtrail/*"
            }
        ]
    }

    try:
        # IAM 역할 생성
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        role_arn = response['Role']['Arn']
        print(f"IAM Role '{role_name}' created successfully with ARN: {role_arn}")

        # 역할에 권한 정책 연결
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(permissions_policy)
        )
        print(f"Policy '{policy_name}' attached to role '{role_name}'.")

        return role_arn

    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Role '{role_name}' already exists.")
        response = iam_client.get_role(RoleName=role_name)
        return response['Role']['Arn']
    except Exception as e:
        print(f"Error creating role or attaching policy: {e}")
        return None

if __name__ == "__main__":
    role_name = "n_macimus_Role"
    policy_name = "n_macimus_Policy"

    role_arn = create_iam_role_for_cloudtrail(role_name, policy_name)
    print(f"Created IAM Role ARN: {role_arn}")
