import boto3

def list_classification_jobs():
    macie_client = boto3.client('macie2')
    try:
        response = macie_client.list_classification_jobs()
        for job in response['items']:
            print(f"Job Name: {job['name']}, Status: {job['jobStatus']}, Type: {job['jobType']}")
    except Exception as e:
        print(f"Error listing classification jobs: {e}")

if __name__ == "__main__":
    list_classification_jobs()
