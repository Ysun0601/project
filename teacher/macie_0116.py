import boto3
import json
from collections import Counter
from time import sleep
import datetime
import re

# Macie 및 S3 클라이언트 초기화
macie2 = boto3.client('macie2', region_name='ap-northeast-2')
s3_client = boto3.client('s3')

def create_classification_job(bucket_name):
    """
    Macie 분류 작업 생성 및 실행
    """
    try:
        # 현재 시간을 기반으로 한 고유한 작업 이름 생성
        job_name = f"sensitive-data-scan-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # 작업 생성 요청
        response = macie2.create_classification_job(
            description='민감 데이터 스캔 작업',
            initialRun=True,
            jobType='ONE_TIME',
            name=job_name,
            s3JobDefinition={
                'bucketDefinitions': [
                    {
                        'accountId': boto3.client('sts').get_caller_identity()['Account'],
                        'buckets': [bucket_name]
                    }
                ]
            }
        )
        
        job_id = response['jobId']
        print(f"분류 작업이 생성되었습니다. Job ID: {job_id}")
        return job_id
    
    except Exception as e:
        print(f"분류 작업 생성 중 오류 발생: {e}")
        return None

def create_custom_data_identifier_with_severity(name, regex, description, threshold=1, severity="HIGH", tags=None):
    """
    사용자 지정 데이터 식별자를 생성하며 심각도 수준, 발생 임계값, 태그를 설정
    """
    try:
        # 기본 요청 데이터 구성
        payload = {
            "name": name,
            "regex": regex,
            "description": description,
            "severityLevels": [
                {
                    "occurrencesThreshold": threshold,
                    "severity": severity
                }
            ]
        }

        # 태그가 존재하는 경우 추가
        if tags:
            payload["tags"] = tags

        # 사용자 지정 데이터 식별자 생성 호출
        response = macie2.create_custom_data_identifier(**payload)
        print(f"생성된 사용자 지정 데이터 식별자 '{name}': {response['customDataIdentifierId']}")
        return response['customDataIdentifierId']
    except Exception as e:
        print(f"데이터 식별자 생성 오류 '{name}': {e}")
        return None

def create_all_identifiers():
    """
    모든 사용자 지정 데이터 식별자를 생성하고 반환하는 함수
    """
    identifiers = {}
    
    # SSN Identifier
    identifiers['ssn'] = create_custom_data_identifier_with_severity(
        name="SSN-Identifier",
        regex=r"\b\d{6}-\d{7}\b",  # 주민등록번호 형식
        description="주민등록번호 형식 탐지",
        threshold=1,
        severity="HIGH",
        tags={"Sensitivity": "HIGH"}
    )

    # CCN Identifier
    identifiers['ccn'] = create_custom_data_identifier_with_severity(
        name="CCN-Identifier",
        regex=r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",  # 신용카드 번호 형식
        description="신용카드 번호 형식 탐지",
        threshold=1,
        severity="HIGH",
        tags={"Sensitivity": "HIGH"}
    )

    # Email Identifier
    identifiers['email'] = create_custom_data_identifier_with_severity(
        name="Email-Identifier",
        regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # 이메일 형식
        description="이메일 주소 탐지",
        threshold=1,
        severity="MEDIUM",
        tags={"Sensitivity": "MEDIUM"}
    )

    # Name Identifier
    identifiers['name'] = create_custom_data_identifier_with_severity(
        name="Name-Identifier",
        regex=r"[가-힣]{2,4}",  # 한글 이름 형식
        description="한글 이름 탐지",
        threshold=1,
        severity="MEDIUM",
        tags={"Sensitivity": "MEDIUM"}
    )
  


    return identifiers

def get_findings():
    """
    Macie 탐지 결과 가져오기 - 개선된 버전
    """
    print("Macie에서 탐지 결과를 가져오는 중...")
    findings = []
    
    try:
        # 7일 전 시간으로 수정
        start_time = int((datetime.datetime.now(datetime.timezone.utc) - 
                         datetime.timedelta(days=7)).timestamp())
        
        paginator = macie2.get_paginator('list_findings')
        
        finding_criteria = {
            'criterion': {
                'type': {
                    'eq': ['SensitiveData:S3Object/Personal']
                },
                'createdAt': {
                    'gte': start_time
                }
            }
        }
        
        try:
            for page in paginator.paginate(
                findingCriteria=finding_criteria,
                sortCriteria={
                    'attributeName': 'createdAt',
                    'orderBy': 'DESC'
                }
            ):
                if page.get('findingIds'):
                    # 한 번에 최대 50개의 findingIds만 처리
                    for i in range(0, len(page['findingIds']), 50):
                        batch = page['findingIds'][i:i+50]
                        response = macie2.get_findings(findingIds=batch)
                        if response.get('findings'):
                            findings.extend(response['findings'])
                            print(f"- {len(response['findings'])}개의 결과를 가져왔습니다.")
                        # API 제한 방지를 위한 지연
                        sleep(0.5)
        
        except macie2.exceptions.ValidationException as ve:
            print(f"검증 오류 발생: {ve}")
            return []
    
    except Exception as e:
        print(f"탐지 결과 조회 중 오류 발생: {e}")
        return []
    
    print(f"\n총 {len(findings)}개의 탐지 결과를 찾았습니다.")
    return findings

def save_findings_to_file(findings, file_name="macie_findings.json"):
    """
    개선된 탐지 결과 저장 함수
    """
    try:
        def custom_serializer(obj):
            if isinstance(obj, (datetime.date, datetime.datetime)):
                return obj.isoformat()
            return str(obj)

        # 저장할 데이터 구조화
        formatted_findings = []
        for finding in findings:
            formatted_finding = {
                'id': finding.get('id'),
                'severity': finding.get('severity', {}).get('description'),
                'created_at': finding.get('createdAt'),
                'object_info': finding.get('resourcesAffected', {}).get('s3Object', {}),
                'sensitive_data': finding.get('sensitiveData', []),
                'type': finding.get('type')
            }
            formatted_findings.append(formatted_finding)

        with open(file_name, "w", encoding="utf-8") as file:
            json.dump(formatted_findings, file, ensure_ascii=False, indent=4, default=custom_serializer)
        print(f"탐지 결과가 {file_name}에 저장되었습니다")
    except Exception as e:
        print(f"파일 저장 오류: {e}")

def analyze_object_content(bucket_name, key):
    """
    S3 객체의 내용을 분석하여 민감도 수준을 결정
    다양한 인코딩 처리
    """
    try:
        # S3 객체 내용 가져오기
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        content_bytes = response['Body'].read()

        # 다양한 인코딩 시도
        encodings = ['utf-8', 'euc-kr', 'cp949', 'iso-8859-1']
        content = None

        for encoding in encodings:
            try:
                content = content_bytes.decode(encoding)
                print(f"성공적으로 디코딩됨 ({encoding}): {key}")
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            print(f"인코딩 실패: {key}")
            return "LOW"

        # 파일 확장자 확인
        file_extension = key.lower().split('.')[-1] if '.' in key else ''
        
        # 바이너리 파일 타입 처리 제외
        binary_extensions = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip', 'exe', 'bin',}
        if file_extension in binary_extensions:
            print(f"바이너리 파일 제외됨: {key}")
            return "NONE"

        # 민감 정보 패턴 정의
        patterns = {
            'HIGH': [
                r"\b\d{6}-\d{7}\b",  # 주민등록번호
                r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",  # 신용카드 번호
            ],
            'MEDIUM': [
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # 이메일
                r"[가-힣]{2,4}",  # 한글 이름               
            ]
            
        }

        # 각 패턴별 매칭 횟수 확인
        matches = {
            'HIGH': 0,
            'MEDIUM': 0
        }

        for level, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches[level] += len(re.findall(pattern, content))

        # 민감도 수준 결정
        if matches['HIGH'] > 0:
            return "HIGH"
        elif matches['MEDIUM'] > 0:
            return "MEDIUM"
        return "LOW"

    except Exception as e:
        print(f"객체 분석 오류 {key}: {e}")
        return "LOW"

def update_object_tags(bucket_name):
    """
    버킷 내 모든 객체의 내용을 분석하고 태그 업데이트
    """
    try:
        objects = []
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects.extend(page['Contents'])

        print(f"분석할 객체 수: {len(objects)}")

        for obj in objects:
            key = obj['Key']
            print(f"\n객체 분석 중: {key}")

            # 객체 내용 분석하여 민감도 결정
            sensitivity = analyze_object_content(bucket_name, key)

            try:
                # 태그 업데이트
                s3_client.put_object_tagging(
                    Bucket=bucket_name,
                    Key=key,
                    Tagging={
                        'TagSet': [
                            {
                                'Key': 'sensitivity',
                                'Value': sensitivity
                            }
                        ]
                    }
                )
                print(f"태그 업데이트 완료 - {key}: {sensitivity}")

            except Exception as e:
                print(f"태그 업데이트 실패 - {key}: {e}")

    except Exception as e:
        print(f"객체 목록 조회 실패: {e}")

def process_findings(findings, bucket_name):
    """
    개선된 Macie 탐지 결과 처리 및 통계 생성
    """
    if not findings:
        print("처리할 탐지 결과가 없습니다")
        return

    stats = {
        'total_findings': len(findings),
        'sensitivity_levels': Counter(),
        'affected_objects': set(),
        'finding_types': Counter(),
        'detection_details': []
    }

    for finding in findings:
        # 기본 정보 수집
        severity = finding.get('severity', {}).get('description', 'UNKNOWN')
        stats['sensitivity_levels'][severity] += 1
        
        # 탐지 유형 집계
        finding_type = finding.get('type', 'UNKNOWN')
        stats['finding_types'][finding_type] += 1
        
        # S3 객체 정보 수집
        s3_object = finding.get('resourcesAffected', {}).get('s3Object', {})
        if s3_object:
            object_key = s3_object.get('key')
            stats['affected_objects'].add(object_key)
            
            # 상세 탐지 정보 수집
            detail = {
                'object_key': object_key,
                'severity': severity,
                'finding_type': finding_type,
                'created_at': finding.get('createdAt'),
                'sensitive_data': []
            }
            
            # 민감 데이터 상세 정보
            if 'sensitiveData' in finding:
                for data in finding['sensitiveData']:
                    detail['sensitive_data'].append({
                        'category': data.get('category'),
                        'count': data.get('detections', {}).get('count', 0),
                        'type': data.get('detections', {}).get('type')
                    })
            
            stats['detection_details'].append(detail)

    # 통계 출력
    print("\n=== 탐지 결과 상세 통계 ===")
    print(f"총 탐지 건수: {stats['total_findings']}")
    
    print("\n민감도 수준별 분포:")
    for level, count in stats['sensitivity_levels'].items():
        print(f"- {level}: {count}건")
    
    print("\n탐지 유형별 분포:")
    for type_name, count in stats['finding_types'].items():
        print(f"- {type_name}: {count}건")
    
    print(f"\n영향받은 객체 수: {len(stats['affected_objects'])}")
    
    print("\n상세 탐지 정보:")
    for detail in stats['detection_details']:
        print(f"\n파일: {detail['object_key']}")
        print(f"심각도: {detail['severity']}")
        print("탐지된 민감 정보:")
        for data in detail['sensitive_data']:
            print(f"- {data['category']}: {data['count']}건")

    return stats

def wait_for_job_completion(job_id, timeout_minutes=5):
    """
    분류 작업 완료 대기
    """
    try:
        print(f"작업 완료 대기 중... (최대 {timeout_minutes}분)")
        start_time = datetime.datetime.now()
        
        while True:
            response = macie2.describe_classification_job(jobId=job_id)
            status = response['jobStatus']
            
            if status == 'COMPLETE':
                print("작업이 성공적으로 완료되었습니다.")
                return True
            elif status == 'FAILED':
                print(f"작업이 실패했습니다: {response.get('errorMessage', '알 수 없는 오류')}")
                return False
            elif status in ['RUNNING', 'IDLE']:
                current_time = datetime.datetime.now()
                elapsed_minutes = (current_time - start_time).total_seconds() / 60
                
                if elapsed_minutes > timeout_minutes:
                    print(f"타임아웃: {timeout_minutes}분이 경과했습니다.")
                    return False
                
                print(f"작업 진행 중... (상태: {status})")
                sleep(30)  # 30초 대기
            else:
                print(f"예상치 못한 작업 상태: {status}")
                return False
                
    except Exception as e:
        print(f"작업 상태 확인 중 오류 발생: {e}")
        return False


if __name__ == "__main__":
    try:
        bucket_name = input("bucket name : ")
        
        # 1. 사용자 지정 데이터 식별자 생성
        print("\n1. 사용자 지정 데이터 식별자 생성 중...")
        identifiers = create_all_identifiers()
        
        # 2. Macie 분류 작업 생성
        print("\n2. Macie 분류 작업 생성 중...")
        job_id = create_classification_job(bucket_name)
        
        if job_id:
            # 3. 객체 분석 중
            print("\n3. 객체 분석 중...")
            
            try:
                objects = []
                analysis_results = []
                
                # S3 객체 목록 조회
                paginator = s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name):
                    if 'Contents' in page:
                        objects.extend(page['Contents'])

                print(f"분석할 객체 수: {len(objects)}")

                # 각 객체 분석
                for obj in objects:
                    key = obj['Key']
                    print(f"\n객체 분석 중: {key}")

                    # 객체 내용 분석하여 민감도 결정
                    sensitivity = analyze_object_content(bucket_name, key)
                    
                    # 분석 결과 저장
                    result = {
                        'object_key': key,
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat(),
                        'sensitivity_level': sensitivity
                    }
                    analysis_results.append(result)

                    # 태그 업데이트
                    try:
                        s3_client.put_object_tagging(
                            Bucket=bucket_name,
                            Key=key,
                            Tagging={
                                'TagSet': [
                                    {
                                        'Key': 'sensitivity',
                                        'Value': sensitivity
                                    }
                                ]
                            }
                        )
                        print(f"태그 업데이트 완료 - {key}: {sensitivity}")

                    except Exception as e:
                        print(f"태그 업데이트 실패 - {key}: {e}")
                        result['tag_update_error'] = str(e)

                # 4. 분석 결과를 JSON 파일로 저장
                print("\n4. 객체 분석 결과를 파일로 저장 중...")
                output_file = "object_sensitivity_analysis.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        'analysis_date': datetime.datetime.now().isoformat(),
                        'bucket_name': bucket_name,
                        'total_objects': len(objects),
                        'results': analysis_results
                    }, f, ensure_ascii=False, indent=4)

                print(f"\n분석 결과가 {output_file}에 저장되었습니다.")

            except Exception as e:
                print(f"객체 분석 및 저장 중 오류 발생: {e}")
        else:
            print("\nMacie 작업 생성에 실패했습니다.")

    except Exception as e:
        print(f"\n실행 중 오류 발생: {str(e)}")
        raise

    finally:
        print("\n스크립트 실행 완료")
