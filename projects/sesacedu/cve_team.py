"""새싹에듀에서 팀이 직접 다룬 CVE — 수사보드의 CVE 후보 맨 위에 '팀 확인' 으로 올라간다.

NVD 는 "이 버전이면 해당될 수 있다" 까지만 말해 준다. 실제로 됐는지는 팀 기록에만 있다.
그래서 여기 적는 것은 **08_모의해킹 문서에 상태가 적힌 것뿐**이다. 상태는 지침의 4단계
(확인 · 코드 확인 · 추정 · 미확인)를 그대로 쓰고, 문서보다 앞서 나가지 않는다.

    roles    이 CVE 가 걸린 서버의 대상 역할(projects/sesacedu/__init__.py 의 roles)
    product  관찰한 버전과 맞춰 볼 제품 이름(dashboard/cve.py 의 PRODUCTS 와 같은 표기)
    seen     밖에서 버전이 보이는지 — 배너·오류 페이지로 레드팀이 알 수 있었나.
             SBOM 으로만 아는 것은 False. 디브리핑에서 '밖에서 몰랐지만 있던 것' 이 된다.
    tactic   보드에 놓일 전술 기본값

출처: 08_모의해킹/README.md 진단 현황 표, cve_매핑/01_SBOM_CVE_전수매핑_2026-11-17.md
"""

CVE_TEAM = [
    {"id": "CVE-2021-44228", "name": "Log4Shell (log4j JNDI 원격 코드 실행)",
     "product": "log4j-core", "version": "2.14.1", "roles": ["user_web"],
     "status": "확인", "date": "11-09", "seen": False, "tactic": "TA0001", "technique": "T1190",
     "note": "head.jspf 가 요청 헤더를 log4j 로 기록 → 리버스 셸 uid=999(tomcat). 이후 임플란트·크론탭(11-14)",
     "doc": "08_모의해킹/log4shell/README.md"},
    {"id": "CVE-2025-24813", "name": "Tomcat partial PUT 역직렬화 원격 코드 실행",
     "product": "Apache Tomcat", "version": "10.1.1", "roles": ["user_web"],
     "status": "확인", "date": "11-17", "seen": True, "tactic": "TA0001", "technique": "T1190",
     "note": "전제 조건(web 톰캣 readonly=false·allowPartialPut) 서버에서 확인. 공격 실행 기록은 없음",
     "doc": "08_모의해킹/cve_매핑/01_SBOM_CVE_전수매핑_2026-11-17.md"},
    {"id": "", "name": "React2Shell (Next.js RSC 역직렬화 원격 코드 실행)",
     "product": "Next.js", "version": "16.0.6", "roles": ["admin_web"],
     "status": "확인", "date": "11-11", "seen": False, "tactic": "TA0001", "technique": "T1190",
     "note": "POST /login 에 execSync('id') → uid=995(adminweb). 팀 문서에 CVE 번호는 적혀 있지 않다",
     "doc": "08_모의해킹/README.md"},
    {"id": "CVE-2021-44832", "name": "log4j JDBC Appender 원격 코드 실행",
     "product": "log4j-core", "version": "2.14.1", "roles": ["user_web"],
     "status": "코드 확인", "date": "11-17", "seen": False, "tactic": "TA0002", "technique": "T1059",
     "note": "설정 파일을 쓸 수 있어야 하는 조건부. 내부 침투 뒤 2차 경로 후보",
     "doc": "08_모의해킹/cve_매핑/01_SBOM_CVE_전수매핑_2026-11-17.md"},
    {"id": "CVE-2024-38819", "name": "Spring 정적 리소스 경로 조작",
     "product": "Spring Framework", "version": "5.3.31", "roles": ["user_web"],
     "status": "코드 확인", "date": "11-17", "seen": False, "tactic": "TA0001", "technique": "T1190",
     "note": "조건부(7.5~9.8)", "doc": "08_모의해킹/cve_매핑/01_SBOM_CVE_전수매핑_2026-11-17.md"},
    {"id": "CVE-2022-1471", "name": "SnakeYAML 역직렬화 원격 코드 실행",
     "product": "SnakeYAML", "version": "1.30", "roles": ["user_web"],
     "status": "코드 확인", "date": "11-17", "seen": False, "tactic": "TA0002", "technique": "T1059",
     "note": "사용자 YAML 입력 경로가 있어야 하는 조건부", "doc": "08_모의해킹/cve_매핑/01_SBOM_CVE_전수매핑_2026-11-17.md"},
    {"id": "CVE-2024-45801", "name": "swagger-ui 번들 DOMPurify DOM XSS",
     "product": "swagger-ui", "version": "4.18.2", "roles": ["user_web"],
     "status": "추정", "date": "11-17", "seen": False, "tactic": "TA0002", "technique": "T1059.007",
     "note": "?configUrl= 경로 추정", "doc": "08_모의해킹/cve_매핑/01_SBOM_CVE_전수매핑_2026-11-17.md"},
]
