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
