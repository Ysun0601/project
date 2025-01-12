import boto3

def create_log_group(log_group_name):
    logs_client = boto3.client('logs', region_name='ap-northeast-2')
    try:
        logs_client.create_log_group(logGroupName=log_group_name)
        print(f"Log group '{log_group_name}' created successfully.")
    except logs_client.exceptions.ResourceAlreadyExistsException:
        print(f"Log group '{log_group_name}' already exists.")
    except Exception as e:
        print(f"Error creating log group: {e}")

if __name__ == "__main__":
    log_group_name = "/aws/cloudtrail/n-macimus-group"
    create_log_group(log_group_name)
