import boto3

cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')

response = cloudtrail_client.lookup_events(
    LookupAttributes=[
        {"AttributeKey": "EventName", "AttributeValue": "GetObject"}
    ],
    MaxResults=10
)

for event in response.get("Events", []):
    print(event)
