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
        name="Korean SSN Pattern",
        regex=r"\d{6}[-]\d{7}",
        description="한국 주민등록번호 패턴",
        severity="HIGH"
    )
    
    # Email Identifier
    identifiers['email'] = create_custom_data_identifier_with_severity(
        name="Email Pattern",
        regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        description="이메일 주소 패턴",
        severity="MEDIUM"
    )
    
    # Phone Number Identifier
    identifiers['phone'] = create_custom_data_identifier_with_severity(
        name="Korean Phone Number Pattern",
        regex=r"\d{2,3}[-]\d{3,4}[-]\d{4}",
        description="한국 전화번호 패턴",
        severity="MEDIUM"
    )
    
    return identifiers

def analyze_object_content(bucket_name, key):
    """
    S3 객체의 내용을 분석하여 민감도 수준을 결정하고 발견된 민감 정보를 추출
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
            return {"sensitivity": "LOW", "findings": {}}

        # 파일 확장자 확인
        file_extension = key.lower().split('.')[-1] if '.' in key else ''
        
        # 바이너리 파일 타입 처리 제외
        binary_extensions = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip', 'exe', 'bin'}
        if file_extension in binary_extensions:
            print(f"바이너리 파일 제외됨: {key}")
            return {"sensitivity": "NONE", "findings": {}}

        # 민감 정보 패턴 정의
        patterns = {
            'HIGH': {
                '주민등록번호': r"\b\d{6}-\d{7}\b",
                '신용카드번호': r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",
                '계좌번호': r"\b\d{11,14}\b",
                '여권번호': r"[A-Z]\d{8}\b",
            },
            'MEDIUM': {
                '이메일': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                '한글이름': r"[가-힣]{2,4}",
                '전화번호': r"\b\d{2,3}[-\s]?\d{3,4}[-\s]?\d{4}\b",
                '주소': r"[서울|경기|인천|대전|광주|대구|울산|부산|강원|충청|전라|경상|제주][가-힣]*\s[가-힣]+[시군구]\s[가-힣]+[동로길]",
            }
        }

        # 발견된 민감 정보 저장
        findings = {
            'HIGH': {},
            'MEDIUM': {},
            'total_count': 0
        }

        highest_sensitivity = "LOW"

        # 각 패턴별 매칭 확인 및 추출
        for level, pattern_dict in patterns.items():
            for pattern_name, pattern in pattern_dict.items():
                matches = re.finditer(pattern, content)
                found_items = [match.group() for match in matches]
                
                if found_items:
                    # 중복 제거
                    unique_items = list(set(found_items))
                    findings[level][pattern_name] = {
                        'count': len(found_items),
                        'unique_count': len(unique_items),
                        'samples': unique_items[:5]  # 최대 5개 샘플만 저장
                    }
                    findings['total_count'] += len(found_items)
                    
                    if level == 'HIGH':
                        highest_sensitivity = "HIGH"
                    elif level == 'MEDIUM' and highest_sensitivity != "HIGH":
                        highest_sensitivity = "MEDIUM"

        return {
            "sensitivity": highest_sensitivity,
            "findings": findings
        }

    except Exception as e:
        print(f"객체 분석 오류 {key}: {e}")
        return {"sensitivity": "LOW", "findings": {}}

if __name__ == "__main__":
    try:
        bucket_name = "macimus-user-data-2"
        
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

                    # 객체 내용 분석하여 민감도 결정 및 민감 정보 추출
                    analysis_result = analyze_object_content(bucket_name, key)
                    
                    # 분석 결과 저장
                    result = {
                        'object_key': key,
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat(),
                        'sensitivity_level': analysis_result['sensitivity'],
                        'sensitive_data_findings': analysis_result['findings']
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
                                        'Value': analysis_result['sensitivity']
                                    }
                                ]
                            }
                        )
                        print(f"태그 업데이트 완료 - {key}: {analysis_result['sensitivity']}")
                        
                        # 발견된 민감 정보 요약 출력
                        if analysis_result['findings']['total_count'] > 0:
                            print("\n발견된 민감 정보 요약:")
                            for level in ['HIGH', 'MEDIUM']:
                                if analysis_result['findings'][level]:
                                    print(f"\n{level} 수준 발견사항:")
                                    for pattern_name, details in analysis_result['findings'][level].items():
                                        print(f"- {pattern_name}: {details['count']}건 발견 (고유 항목: {details['unique_count']}개)")

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
