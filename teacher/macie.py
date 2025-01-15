import boto3
import json
from collections import Counter
from time import sleep
import datetime
import re
# 이게 진짜 코드야!!
# Macie 및 S3 클라이언트 초기화
macie2 = boto3.client('macie2', region_name='ap-northeast-2')
s3_client = boto3.client('s3')

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
    Macie 탐지 결과 가져오기
    """
    print("Macie에서 탐지 결과를 가져오는 중...")
    findings = []
    
    try:
        # 24시간 전 시간 계산 및 정수로 변환
        start_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp() - 24 * 3600)
        
        paginator = macie2.get_paginator('list_findings')
        
        # AWS Macie2 API 형식에 맞춘 필터 기준
        finding_criteria = {
            'criterion': {
                'type': {
                    'eq': ['SENSITIVE_DATA']
                },
                'severity.description': {
                    'eq': ['High']
                },
                'createdAt': {
                    'gte': start_time  # 정수형으로 변환된 timestamp
                }
            }
        }
        
        try:
            # 페이지네이션을 사용하여 결과 조회
            for page in paginator.paginate(
                findingCriteria=finding_criteria,
                sortCriteria={
                    'attributeName': 'createdAt',
                    'orderBy': 'DESC'
                },
                maxResults=100
            ):
                if page.get('findingIds'):
                    response = macie2.get_findings(findingIds=page['findingIds'])
                    if response.get('findings'):
                        findings.extend(response['findings'])
                        print(f"- {len(response['findings'])}개의 결과를 가져왔습니다.")
        
        except macie2.exceptions.ValidationException as ve:
            print(f"필터 검증 오류 발생: {ve}")
            print("필터 없이 전체 결과를 조회합니다...")
            
            # 필터 없이 재시도
            for page in paginator.paginate(maxResults=100):
                if page.get('findingIds'):
                    response = macie2.get_findings(findingIds=page['findingIds'])
                    if response.get('findings'):
                        findings.extend(response['findings'])
                        print(f"- {len(response['findings'])}개의 결과를 가져왔습니다.")
    
    except Exception as e:
        print(f"탐지 결과 조회 중 오류 발생: {e}")
        return []
    
    print(f"\n총 {len(findings)}개의 탐지 결과를 찾았습니다.")
    
    # 디버깅을 위한 시간 정보 출력
    print(f"\n조회 시작 시간: {datetime.datetime.fromtimestamp(start_time, datetime.timezone.utc)}")
    
    return findings

def save_findings_to_file(findings, file_name="macie_findings.json"):
    """
    탐지 결과를 JSON 파일로 저장
    """
    try:
        def custom_serializer(obj):
            if isinstance(obj, (datetime.date, datetime.datetime)):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        with open(file_name, "w", encoding="utf-8") as file:
            json.dump(findings, file, ensure_ascii=False, indent=4, default=custom_serializer)
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
        binary_extensions = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip', 'exe', 'bin', }
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
    Macie 탐지 결과를 처리하고 통계 생성
    """
    if not findings:
        print("처리할 탐지 결과가 없습니다")
        return

    # 통계 초기화
    stats = {
        'total_findings': len(findings),
        'sensitivity_levels': Counter(),
        'affected_objects': set()
    }

    for finding in findings:
        # 민감도 수준 집계
        severity = finding.get('severity', {}).get('description', 'UNKNOWN')
        stats['sensitivity_levels'][severity] += 1
        
        # 영향받은 객체 추적
        s3_object = finding.get('resourcesAffected', {}).get('s3Object', {})
        if s3_object:
            stats['affected_objects'].add(s3_object.get('key'))

    # 통계 출력
    print("\n=== 탐지 결과 통계 ===")
    print(f"총 탐지 건수: {stats['total_findings']}")
    print("\n민감도 수준별 분포:")
    for level, count in stats['sensitivity_levels'].items():
        print(f"- {level}: {count}건")
    print(f"\n영향받은 객체 수: {len(stats['affected_objects'])}")

    return stats

if __name__ == "__main__":
    try:
        bucket_name = "n-macimus-sensitive-data"  # 실제 버킷 이름으로 변경
        job_name = f"macimus-test-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # 사용자 지정 데이터 식별자 생성
        print("사용자 지정 데이터 식별자 생성 중...")
        identifiers = create_all_identifiers()
        
        # 객체 내용 분석 및 태그 업데이트
        print("\n객체 분석 및 태그 업데이트 시작...")
        update_object_tags(bucket_name)

        # Macie 탐지 결과 가져오기
        print("\nMacie 탐지 결과 조회 중...")
        findings = get_findings()

        # 탐지 결과 처리 및 통계 생성
        stats = process_findings(findings, bucket_name)

        # 결과 저장
        save_findings_to_file(findings)

    except Exception as e:
        print(f"실행 중 오류 발생: {str(e)}")
        raise

    finally:
        print("\n스크립트 실행 완료")
