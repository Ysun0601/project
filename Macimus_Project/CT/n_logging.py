import boto3

# CloudTrail 클라이언트 생성
cloudtrail_client = boto3.client('cloudtrail', region_name='ap-northeast-2')

# 기존 추적 이름과 S3 버킷 이름
trail_name = 'n-team4-m-new-trail'  # 기존 CloudTrail 추적 이름으로 변경
bucket_name = 'n-macimus-sensitive-data'  # S3 버킷 이름으로 변경

# 데이터 이벤트 로깅 활성화
response = cloudtrail_client.put_event_selectors(
    TrailName=trail_name,
    EventSelectors=[
        {
            'ReadWriteType': 'All',  # 'ReadOnly' 또는 'WriteOnly'로 설정 가능
            'IncludeManagementEvents': True,  # 관리 이벤트 포함 여부
            'DataResources': [
                {
                    'Type': 'AWS::S3::Object',
                    'Values': [f'arn:aws:s3:::{bucket_name}/*']
                }
            ]
        }
    ]
)

print(response)
