import boto3

macie_client = boto3.client('macie2')

def lambda_handler(event, context):
    try:
        # EventBridge 이벤트에서 Job ID 추출
        job_id = event['detail']['jobId']
        print(f"Triggered by Job ID: {job_id}")
        
        # Macie 탐지 결과 가져오기
        findings = macie_client.list_findings()
        finding_ids = findings.get("findingIds", [])
        
        if not finding_ids:
            print("No findings detected.")
            return {"message": "No findings detected"}
        
        # 탐지된 결과 가져오기
        response = macie_client.get_findings(findingIds=finding_ids)
        sensitive_results = response.get('findings', [])
        
        # 결과를 분석하거나 저장
        for finding in sensitive_results:
            print(f"Finding ID: {finding['id']}")
            print(f"Severity: {finding['severity']['description']}")
            print(f"Sensitive Data: {finding.get('classificationDetails', {}).get('result', {}).get('sensitiveData', [])}")
        
        return {"message": "Findings processed successfully"}
    
    except Exception as e:
        print(f"Error processing Macie findings: {e}")
        return {"error": str(e)}
