import boto3

def setup_cloudwatch_logs_for_cloudtrail(trail_name, log_group_arn, role_arn):
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
    trail_name = "n-macimus-trail"
    log_group_arn = "arn:aws:logs:ap-northeast-2:423623825149:log-group:/aws/cloudtrail/n-macimus-group:*"
    role_arn = "arn:aws:iam::423623825149:role/n_macimus_Role"

    setup_cloudwatch_logs_for_cloudtrail(trail_name, log_group_arn, role_arn)
