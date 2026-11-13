"""경로가 무슨 의미인지 아는 표 — 찾은 것에 설명과 민감도를 붙인다.

퍼징은 경로를 **찾을** 뿐이고, 그것이 무엇인지는 모른다. `/etc/sesacedu/api.env` 를
찾아 놓고 `api.env [200 · 389B]` 라고만 적으면 보고서를 읽는 사람이 왜 중요한지 모른다.

두 군데서 모았다.
  씨앗 지식   `08_모의해킹/file_inclusion/fsmap/core/seeds.py` — 패키지를 깔면 생기는 경로
  11-04 실측  실제로 읽어 보고 적은 설명 — **이쪽이 이긴다**(추측이 아니라 본 것이다)

표에 없는 경로는 `_RULES` 의 생김새로 짐작한다. 짐작한 것은 설명 끝에 `(추정)` 을 붙여
본 것과 구분한다 — 안 그러면 보고서에서 둘이 같아 보인다.
"""

# 경로(맨 앞 / 없음) → (설명, 민감도)
KNOWN = {
    "app":                                                   ("컨테이너식 배치 후보", "info"),
    "data":                                                  ("데이터 볼륨 후보", "info"),
    "etc/apt/sources.list":                                  ("저장소 설정", "info"),
    "etc/crontab":                                           ("정기 작업", "medium"),
    "etc/default/tomcat10":                                  ("기동 옵션·JAVA_OPTS", "high"),
    "etc/default/tomcat9":                                   ("기동 옵션·JAVA_OPTS", "high"),
    "etc/environment":                                       ("전역 환경변수", "medium"),
    "etc/fstab":                                             ("마운트 구성 — 별도 볼륨이 있는지", "low"),
    "etc/group":                                             ("그룹 목록 — 앱 계정이 어느 그룹인지", "low"),
    "etc/hostname":                                          ("호스트명", "info"),
    "etc/hosts":                                             ("내부 이름 매핑 — 사설 IP 가 보일 수 있다", "medium"),
    "etc/letsencrypt":                                       ("루트", "info"),
    "etc/letsencrypt/live/sesacedu.store/fullchain.pem":     ("인증서", "low"),
    "etc/letsencrypt/live/sesacedu.store/privkey.pem":       ("**개인키** — 읽히면 치명적. 보통 0700 으로 500", "critical"),
    "etc/letsencrypt/renewal/sesacedu.store.conf":           ("갱신 설정", "low"),
    "etc/machine-id":                                        ("머신 식별자", "info"),
    "etc/nginx":                                             ("설정 루트", "info"),
    "etc/nginx/conf.d":                                      ("추가 설정", "info"),
    "etc/nginx/mime.types":                                  ("MIME 매핑(존재 확인용)", "info"),
    "etc/nginx/modules-enabled":                             ("활성 모듈", "info"),
    "etc/nginx/nginx.conf":                                  ("메인 설정", "medium"),
    "etc/nginx/proxy_params":                                ("프록시 기본 헤더", "info"),
    "etc/nginx/sites-available":                             ("가상호스트 정의", "info"),
    "etc/nginx/sites-available/default":                     ("기본 가상호스트", "low"),
    "etc/nginx/sites-available/sesacedu":                    ("서비스 가상호스트 — 11-03 실독 성공", "high"),
    "etc/nginx/sites-available/sesacedu-admin":              ("관리자 웹 8443 가상호스트 — 11-04 신규 생성", "high"),
    "etc/nginx/sites-enabled":                               ("활성 가상호스트(심볼릭 링크)", "info"),
    "etc/nginx/snippets":                                    ("조각 설정", "info"),
    "etc/os-release":                                        ("배포판·버전", "info"),
    "etc/passwd":                                            ("계정 목록", "medium"),
    "etc/resolv.conf":                                       ("DNS — VPC 내부 리졸버가 보인다", "low"),
    "etc/sesacedu/api.env":                                  ("DB·JWT 서명키·메일 비밀번호 노출", "critical"),
    "etc/shadow":                                            ("읽히면 치명적. 보통 500(권한 정상)", "critical"),
    "etc/sudoers":                                           ("권한 설정. 보통 500", "high"),
    "etc/systemd/system":                                    ("관리자가 만든 유닛이 있는 디렉터리", "info"),
    "etc/systemd/system/multi-user.target.wants":            ("자동 시작 목록", "info"),
    "etc/systemd/system/sesacedu-admin-web.service":         ("관리자 웹 유닛 — 작업일지 11-04 에 실제로 등장한 이름", "high"),
    "etc/systemd/system/sesacedu-api.service":               ("배포 절대경로 전부 노출", "high"),
    "etc/systemd/system/sesacedu-web.service":               ("배포 절대경로 전부 노출", "high"),
    "etc/systemd/system/sesacedu.service":                   ("유닛(이름 추정)", "high"),
    "etc/timezone":                                          ("시간대 — 로그 시각 해석에 필요", "info"),
    "etc/tomcat10":                                          ("설정(10)", "info"),
    "etc/tomcat10/context.xml":                              ("컨텍스트·DB 자원", "high"),
    "etc/tomcat10/server.xml":                               ("커넥터·포트", "high"),
    "etc/tomcat10/tomcat-users.xml":                         ("관리 계정", "critical"),
    "etc/tomcat9":                                           ("설정(9)", "info"),
    "etc/tomcat9/context.xml":                               ("컨텍스트·DB 자원", "high"),
    "etc/tomcat9/server.xml":                                ("커넥터·포트", "high"),
    "etc/tomcat9/tomcat-users.xml":                          ("관리 계정", "critical"),
    "home/alice":                                            ("설명되지 않은 계정의 홈", "high"),
    "home/alice/.bash_history":                              ("같은 계정의 명령 이력", "critical"),
    "home/ubuntu":                                           ("배포 루트 후보(가장 흔함)", "info"),
    "home/ubuntu/.aws/credentials":                          ("AWS 키가 있으면 치명적", "critical"),
    "home/ubuntu/.bash_history":                             ("실행한 명령 이력 — 0600 이라 보통 500", "critical"),
    "home/ubuntu/.ssh/authorized_keys":                      ("접속 허용 공개키", "high"),
    "home/ubuntu/storage":                                   ("홈 하위 저장소 후보", "low"),
    "lib/systemd/system":                                    ("패키지가 넣은 유닛", "info"),
    "opt/java/jdk-11.0.24+8/release":                        ("Temurin JDK 11.0.24 (apt 밖 tarball)", "medium"),
    "opt/sesacedu":                                          ("배포 루트 후보", "info"),
    "opt/sesacedu/application.properties":                   ("설정", "critical"),
    "opt/sesacedu/application.yml":                          ("설정 — DB 접속정보가 있다", "critical"),
    "opt/sesacedu/config/application.yml":                   ("설정(config 하위)", "critical"),
    "opt/sesacedu/storage":                                  ("배포 루트 하위 저장소 후보", "low"),
    "opt/tomcat":                                            ("설치 루트(가장 흔한 위치)", "info"),
    "opt/tomcat/bin/setenv.sh":                              ("기동 환경변수 — 비밀값이 들어가곤 한다", "critical"),
    "opt/tomcat/conf/catalina.properties":                   ("클래스패스", "medium"),
    "opt/tomcat/conf/context.xml":                           ("컨텍스트", "high"),
    "opt/tomcat/conf/server.xml":                            ("커넥터·포트", "high"),
    "opt/tomcat/conf/tomcat-users.xml":                      ("관리 계정", "critical"),
    "opt/tomcat/logs/catalina.out":                          ("표준출력 로그", "high"),
    "opt/tomcat/webapps":                                    ("배포 웹앱", "info"),
    "opt/tomcat/webapps/ROOT":                               ("루트 컨텍스트", "info"),
    "proc/version":                                          ("커널 버전", "info"),
    "root/.bash_history":                                    ("root 명령 이력", "critical"),
    "run/nginx.pid":                                         ("실행 중 PID", "info"),
    "srv/sesacedu":                                          ("배포 루트 후보", "info"),
    "srv/sesacedu/api/conf/catalina.properties":             ("", "info"),
    "srv/sesacedu/api/conf/context.xml":                     ("", "info"),
    "srv/sesacedu/api/conf/logging.properties":              ("", "info"),
    "srv/sesacedu/api/conf/server.xml":                      ("", "info"),
    "srv/sesacedu/api/conf/tomcat-users.xml":                ("배포 기본값·계정 없음 → Manager 경로 닫힘", "high"),
    "srv/sesacedu/api/conf/web.xml":                         ("", "info"),
    "srv/sesacedu/web/conf/catalina.properties":             ("", "info"),
    "srv/sesacedu/web/conf/context.xml":                     ("", "info"),
    "srv/sesacedu/web/conf/logging.properties":              ("", "info"),
    "srv/sesacedu/web/conf/server.xml":                      ("", "info"),
    "srv/sesacedu/web/conf/tomcat-users.xml":                ("", "info"),
    "srv/sesacedu/web/conf/web.xml":                         ("", "info"),
    "storage":                                               ("상대경로로 잡힌 저장소가 최상위에 있을 가능성", "low"),
    "usr/lib/jvm":                                           ("설치된 JDK 목록", "info"),
    "usr/lib/jvm/java-11-openjdk-amd64/release":             ("JDK 11 여부", "info"),
    "usr/lib/jvm/java-17-openjdk-amd64/release":             ("JDK 17 여부·정확한 버전", "info"),
    "usr/lib/jvm/java-21-openjdk-amd64/release":             ("JDK 21 여부", "info"),
    "usr/lib/systemd/system":                                ("같은 곳(배포판에 따라)", "info"),
    "usr/local/tomcat/conf/server.xml":                      ("다른 수동 설치 위치", "high"),
    "usr/share/nginx/html":                                  ("패키지 기본 문서 루트", "info"),
    "usr/share/tomcat10":                                    ("프로그램 본체", "info"),
    "usr/share/tomcat9":                                     ("프로그램 본체", "info"),
    "var/lib/cloud/instance/obj.pkl":                        ("인스턴스 메타데이터 캐시", "medium"),
    "var/lib/cloud/instance/scripts/part-001":               ("실행된 스크립트", "critical"),
    "var/lib/cloud/instance/user-data.txt":                  ("user-data 원문", "critical"),
    "var/lib/dpkg/status":                                   ("설치된 전체 패키지와 버전", "medium"),
    "var/lib/tomcat10/webapps":                              ("배포된 웹앱", "info"),
    "var/lib/tomcat9/webapps":                               ("배포된 웹앱", "info"),
    "var/log":                                               ("로그 루트", "info"),
    "var/log/apt/history.log":                               ("apt 로 무엇을 깔았는지", "low"),
    "var/log/auth.log":                                      ("인증 로그", "high"),
    "var/log/cloud-init-output.log":                         ("EC2 최초 부팅 때 실행한 스크립트의 출력 — **구축 명령이 그대로 남는다**", "critical"),
    "var/log/cloud-init.log":                                ("cloud-init 동작 로그", "medium"),
    "var/log/dpkg.log":                                      ("설치 시각 순서 — 구축 순서가 보인다", "low"),
    "var/log/journal":                                       ("systemd 저널(바이너리)", "info"),
    "var/log/nginx":                                         ("로그 디렉터리", "info"),
    "var/log/nginx/access.log":                              ("접근 로그 — 내 공격 흔적도 들어 있다", "medium"),
    "var/log/nginx/error.log":                               ("오류 로그 — 업스트림 경로가 보일 수 있다", "medium"),
    "var/log/syslog":                                        ("시스템 로그", "medium"),
    "var/log/tomcat10/catalina.out":                         ("표준출력 로그", "high"),
    "var/log/tomcat9/catalina.out":                          ("표준출력 로그 — 기동 시 경로가 찍힌다", "high"),
    "var/ossec":                                             ("에이전트 루트", "info"),
    "var/ossec/etc/client.keys":                             ("에이전트 등록 키", "critical"),
    "var/ossec/etc/ossec.conf":                              ("수집 대상·관리자 주소 — **무엇을 감시하는지** 알 수 있다", "high"),
    "var/ossec/logs/ossec.log":                              ("에이전트 동작 로그", "medium"),
    "var/www":                                               ("문서 루트 상위", "info"),
    "var/www/html":                                          ("기본 문서 루트", "info"),
    # 11-04 유닛 파일에서 캐낸 것 — 어떤 사전에도 없어 수확으로만 나온다
    "opt/apache-tomcat-10.1.1":                  ("Tomcat 10.1.1 설치 경로 — 유닛의 CATALINA_HOME. 버전이 확정되면 CVE 매칭이 된다", "high"),
    "opt/java/jdk-11.0.24+8":                    ("Temurin JDK 11.0.24 설치 경로 — 유닛의 JAVA_HOME", "medium"),
    "srv/sesacedu/api":                          ("API 배포 디렉터리 — 유닛의 WorkingDirectory", "medium"),
}

# 표에 없을 때 생김새로 짐작한다. 위에서부터 먼저 맞는 것.
_RULES = [
    (("shadow", "gshadow"), "비밀번호 해시", "critical"),
    ((".ssh/id_", ".ssh/authorized_keys"), "SSH 키", "critical"),
    ((".env", "credentials", "secrets"), "자격증명이 들어 있을 수 있는 파일", "critical"),
    ((".key", ".pem", "privkey"), "개인키·인증서", "critical"),
    ((".service", ".timer"), "systemd 유닛 — 배포 절대경로가 적혀 있다", "high"),
    ((".bash_history", ".mysql_history"), "명령 기록", "high"),
    (("tomcat-users.xml", "server.xml", "context.xml"), "Tomcat 설정", "high"),
    (("sites-available/", "sites-enabled/", "nginx.conf"), "nginx 가상호스트·설정", "high"),
    ((".war", ".jar"), "배포 산출물", "medium"),
    (("crontab", "cron.d/"), "정기 작업", "medium"),
    ((".log",), "로그", "low"),
    ((".conf", ".cfg", ".ini", ".yml", ".yaml", ".properties"), "설정 파일", "low"),
]


def describe(path):
    """경로 하나 → (설명, 민감도). 모르면 ("", "info").

    표에 있으면 그대로, 없으면 생김새로 짐작하고 `(추정)` 을 붙인다.
    짐작을 본 것처럼 적으면 보고서가 틀린다.
    """
    key = (path or "").strip("/")
    if key in KNOWN:
        return KNOWN[key]
    low = key.lower()
    for marks, desc, sev in _RULES:
        if any(m in low for m in marks):
            return desc + " (추정)", sev
    return "", "info"
