import boto3

sns_client = boto3.client('sns')
s3_client = boto3.client('s3')
ses_client = boto3.client('ses')
iam_client = boto3.client('iam')
sns_topic_arn = "arn:aws:sns:ap-northeast-2:423623825149:test"

AUTHORIZED_USERS = [
    "arn:aws:iam::423623825149:user/YOO",
    "arn:aws:iam::423623825149:user/Park",
    "arn:aws:iam::423623825149:user/Jung"
]

def send_email_report(subject, body):
    try:
        response = ses_client.send_email(
            Source="admin@example.com",
            Destination={"ToAddresses": ["admin@example.com"]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}}
            }
        )
        print(f"Email sent successfully: {response['MessageId']}")
    except Exception as e:
        print(f"Error sending email: {e}")

def disable_iam_user(user_arn):
    try:
        user_name = user_arn.split("/")[-1]
        response = iam_client.update_user(
            UserName=user_name,
            NewUserName=f"DISABLED_{user_name}"
        )
        print(f"IAM user {user_name} disabled successfully.")
        return f"IAM user {user_name} disabled successfully."
    except Exception as e:
        print(f"Error disabling IAM user: {e}")
        return f"Failed to disable IAM user {user_name}. Error: {e}"

def lambda_handler(event, context):
    try:
        # 디버깅: 이벤트 데이터 확인
        print("Debug: Received event:", event)

        detail = event.get('detail', {})
        bucket_name = detail.get('requestParameters', {}).get('bucketName', 'UnknownBucket')
        object_key = detail.get('requestParameters', {}).get('key', 'UnknownObject')
        user_arn = detail.get('userIdentity', {}).get('arn', 'UnknownUser')
        event_name = detail.get('eventName', 'Unknown Event')

        # 디버깅: 주요 데이터 확인
        print(f"Debug: Bucket Name: {bucket_name}, Object Key: {object_key}, User ARN: {user_arn}, Event Name: {event_name}")

        # 초기 민감도 값 설정
        sensitivity = 'NONE'

        # S3 객체 태그 가져오기
        try:
            response = s3_client.get_object_tagging(Bucket=bucket_name, Key=object_key)
            print("Debug: Tagging Response:", response)
            tags = {tag['Key']: tag['Value'] for tag in response['TagSet']}
            sensitivity = tags.get('sensitivity', 'NONE')
            print(f"Debug: Sensitivity for object '{object_key}': {sensitivity}")
        except Exception as e:
            print(f"Error retrieving tags for object '{object_key}': {e}")
            sensitivity = 'NONE'

        # 조건: 민감도 HIGH + 허가되지 않은 사용자만 처리
        if sensitivity == 'HIGH' and user_arn not in AUTHORIZED_USERS:
            print("Unauthorized access to HIGH sensitivity object detected.")

            # 사용자 비활성화 시도
            action_result = disable_iam_user(user_arn)

            # 이메일 및 SNS 알림
            message = (
                f"🚨 **Unauthorized Access Detected** 🚨\n\n"
                f"**Details:**\n"
                f"- User: {user_arn}\n"
                f"- Event: {event_name}\n"
                f"- Bucket: {bucket_name}\n"
                f"- Object: {object_key}\n"
                f"- Sensitivity: {sensitivity}\n"
            )
            try:
                sns_client.publish(
                    TopicArn=sns_topic_arn,
                    Subject="Unauthorized Access to HIGH Sensitivity Object",
                    Message=message
                )
                print(f"Alert sent: {message}")
            except Exception as sns_error:
                print(f"Error sending SNS alert: {sns_error}")

            send_email_report("[Alert] Unauthorized Access Detected", message)
        else:
            print(f"Access ignored. Sensitivity: {sensitivity}, User: {user_arn}")

        return {"status": "success"}
    except Exception as e:
        print(f"Error processing event: {e}")
        return {"status": "error", "message": str(e)}