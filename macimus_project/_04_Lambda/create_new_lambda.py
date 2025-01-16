import boto3
import zipfile
import os
from ipaddress import ip_address, ip_network

lambda_client = boto3.client('lambda')

def create_lambda_function():

    role_arn = "arn:aws:iam::423623825149:role/LambdaExecutionRole"

    lambda_file = "lambda_function.py"
    zip_file = "lambda_function.zip"

    lambda_code = """import boto3

sns_client = boto3.client('sns')
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
        detail = event.get('detail', {})
        source_ip = detail.get('sourceIPAddress', 'Unknown IP')
        user_arn = detail.get('userIdentity', {}).get('arn', 'UnknownUser')
        event_name = detail.get('eventName', 'Unknown Event')
        bucket_name = detail.get('requestParameters', {}).get('bucketName', 'UnknownBucket')
        object_key = detail.get('requestParameters', {}).get('key', 'UnknownObject')


        reasons = []
        actions_taken = []

        if user_arn not in AUTHORIZED_USERS:
            reasons.append("- Unauthorized user detected")
            action_result = disable_iam_user(user_arn)
            actions_taken.append(action_result)

        if event_name in ["PutObject", "DeleteObject"] and user_arn not in AUTHORIZED_USERS:
            reasons.append("- Unauthorized system resource access detected")

         try:
            s3_tags = s3_client.get_object_tagging(Bucket=bucket_name, Key=object_key)
            tags = {tag['Key']: tag['Value'] for tag in s3_tags['TagSet']}
            sensitivity = tags.get('sensitivity', 'NONE')
            print(f"Object '{object_key}' has sensitivity: {sensitivity}")
        except Exception as e:
            print(f"Error retrieving tags for object '{object_key}': {e}")
            sensitivity = 'NONE'

        # 추가 로직: HIGH 태그가 있는 객체에 대한 무단 접근 감지
        if sensitivity == 'HIGH' and user_arn not in AUTHORIZED_USERS:
            reasons.append("- Unauthorized access to HIGH sensitivity object detected")    

        if reasons:
            # 이유 및 수행된 조치 출력
            reason_text = "\n".join(reasons)
            action_text = "\n".join(actions_taken)
            message = (
                f"🚨 **Unauthorized Access Detected** 🚨\n\n"
                f"**Reasons:**\n{reason_text}\n\n"
                f"**Actions Taken:**\n{action_text}\n\n"
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
                    Subject="Unauthorized Access Detected",
                    Message=message
                )
                print(f"Alert sent: {message}")
            except Exception as sns_error:
                print(f"Error sending SNS alert: {sns_error}")

            email_subject = "[Alert] Unauthorized Access Detected"
            email_body = (
                f"🚨 **Unauthorized Access Detected** 🚨\n\n"
                f"**Reasons:**\n{reason_text}\n\n"
                f"**Actions Taken:**\n{action_text}\n\n"
                f"**Details:**\n"
                f"- Event: {event_name}\n"
                f"- Bucket: {bucket_name}\n"
                f"- Object: {object_key}\n"
            )
            send_email_report(email_subject, email_body)
        else:
            print("No unauthorized access detected.")


        return {"status": "success"}
    except Exception as e:
        print(f"Error processing event: {e}")
        return {"status": "error", "message": str(e)}
    """

    with open(lambda_file, "w", encoding="utf-8") as f:
        f.write(lambda_code)

    try:
        with zipfile.ZipFile(zip_file, 'w') as z:
            z.write(lambda_file)
        print("Lambda ZIP file created successfully.")

        with open(zip_file, 'rb') as f:
            response = lambda_client.create_function(
                FunctionName="DetectUnauthorizedS3Access2",
                Runtime="python3.9",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": f.read()},
                Description="Lambda function to detect unauthorized S3 access and send alerts via SNS",
                Timeout=15,
                MemorySize=128,
                Publish=True
            )
        print(f"Lambda function created successfully: {response['FunctionArn']}")
    except Exception as e:
        print(f"Error creating Lambda function: {e}")
    finally:
        if os.path.exists(lambda_file):
            os.remove(lambda_file)
        if os.path.exists(zip_file):
            os.remove(zip_file)

create_lambda_function()