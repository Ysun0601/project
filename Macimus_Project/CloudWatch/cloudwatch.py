# 통합
import boto3
import json

def create_log_group(log_group_name):
    logs_client = boto3.client('logs', region_name='ap-northeast-2')
    try:
        logs_client.create_log_group(logGroupName=log_group_name)
        print(f"Log group '{log_group_name}' created successfully.")
    except logs_client.exceptions.ResourceAlreadyExistsException:
        print(f"Log group '{log_group_name}' already exists.")
    except Exception as e:
        print(f"Error creating log group: {e}")

def create_iam_role_for_cloudtrail(role_name, policy_name):
    """
    CloudTrail이 CloudWatch 로그 그룹에 기록할 수 있는 IAM 역할 생성 및 정책 추가.
    :param role_name: 생성할 IAM 역할 이름
    :param policy_name: IAM 정책 이름
    :return: IAM 역할 ARN
    """
    iam_client = boto3.client('iam')

    # 역할 신뢰 정책 (CloudTrail 서비스에 역할 위임)
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

    # CloudWatch 로그 그룹에 기록할 수 있는 정책
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:PutLogEvents",
                    "logs:CreateLogStream"
                ],
                "Resource": "arn:aws:logs:ap-northeast-2:423623825149:log-group:/aws/cloudtrail/macimus-group:*"
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

        # IAM 정책 추가
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(inline_policy)
        )
        print(f"Inline policy '{policy_name}' added to role '{role_name}'.")

        return role_arn

    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"IAM Role '{role_name}' already exists.")
        response = iam_client.get_role(RoleName=role_name)
        return response['Role']['Arn']
    except Exception as e:
        print(f"Error creating IAM role or adding policy: {e}")
        return None


def setup_cloudwatch_logs_for_cloudtrail(trail_name, log_group_arn, role_arn):
    """
    CloudTrail 로그를 CloudWatch 로그 그룹으로 전송 설정.
    :param trail_name: CloudTrail 이름
    :param log_group_arn: CloudWatch 로그 그룹 ARN
    :param role_arn: CloudTrail이 사용할 IAM 역할 ARN
    """
    cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')
    try:
        cloudtrail_client.update_trail(
            Name=trail_name,
            CloudWatchLogsLogGroupArn=log_group_arn,
            CloudWatchLogsRoleArn=role_arn
        )
        print(f"CloudTrail '{trail_name}' updated to send logs to CloudWatch log group '{log_group_arn}'.")
    except Exception as e:
        print(f"Error setting up CloudWatch logs for CloudTrail: {e}")


if __name__ == "__main__":
    # CloudWatch 로그 그룹 생성
    log_group_name = "/aws/cloudtrail/macimus-group"
    create_log_group(log_group_name)

    # IAM 역할 및 정책 설정
    role_name = "CloudTrail_CloudWatchLogs_macimus_Role"
    policy_name = "CloudTrailCloudWatchPolicy"

    # CloudTrail 설정
    trail_name = "n2-macimus-trail"
    log_group_arn = "arn:aws:logs:ap-northeast-2:423623825149:log-group:/aws/cloudtrail/macimus-group"

    # 1. IAM 역할 생성 및 ARN 반환
    role_arn = create_iam_role_for_cloudtrail(role_name, policy_name)

    if role_arn:
        # 2. CloudTrail에 CloudWatch 로그 그룹 연결
        setup_cloudwatch_logs_for_cloudtrail(trail_name, log_group_arn, role_arn)
