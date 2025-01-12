import boto3

def create_metric_filter(log_group_name, filter_name, filter_pattern, metric_namespace, metric_name):
    logs_client = boto3.client('logs', region_name='ap-northeast-2')
    try:
        response = logs_client.put_metric_filter(
            logGroupName=log_group_name,
            filterName=filter_name,
            filterPattern=filter_pattern,
            metricTransformations=[
                {
                    'metricName': metric_name,
                    'metricNamespace': metric_namespace,
                    'metricValue': '1'
                }
            ]
        )
        print(f"Metric filter '{filter_name}' created successfully.")
    except Exception as e:
        print(f"Error creating metric filter: {e}")

if __name__ == "__main__":
    log_group_name = "/aws/cloudtrail/n-macimus-group"
    filter_name = "GetObjectFilter"
    #filter_pattern = '{ $.eventName = "GetObject" && $.requestParameters.bucketName = "n-macimus-sensitive-data" }'
    filter_pattern = '{ $.eventName = "GetObject" && $.resources[0].ARN = "arn:aws:s3:::n-macimus-sensitive-data" }'
    metric_namespace = "S3DataAccess"
    metric_name = "GetObjectCount"

    create_metric_filter(log_group_name, filter_name, filter_pattern, metric_namespace, metric_name)
