import boto3
import json

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

    # CloudTrail 설정
    trail_name = "n2-macimus-trail"
    log_group_arn = "arn:aws:logs:ap-northeast-2:423623825149:log-group:/aws/cloudtrail/macimus-group:*"

    role_arn = "arn:aws:iam::423623825149:role/CloudTrail_CloudWatchLogs_macimus_Role"

    if role_arn:
        # 2. CloudTrail에 CloudWatch 로그 그룹 연결
        setup_cloudwatch_logs_for_cloudtrail(trail_name, log_group_arn, role_arn)