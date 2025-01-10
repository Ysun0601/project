import boto3

def enable_data_events(trail_name, sensitive_bucket_name):
    cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')
    try:
        response = cloudtrail_client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': False,
                    'DataResources': [
                        {
                            'Type': 'AWS::S3::Object',
                            'Values': [f"arn:aws:s3:::{sensitive_bucket_name}/*"]
                        }
                    ]
                }
            ]
        )
        print(f"Data events enabled for trail '{trail_name}' on bucket '{sensitive_bucket_name}'.")
    except Exception as e:
        print(f"Error enabling data events: {e}")

if __name__ == "__main__":
    trail_name = "macimus-data-cloudtrail"
    sensitive_bucket_name = "macimus-userdata"
    enable_data_events(trail_name, sensitive_bucket_name)
