"""새싹에듀 구성(Tomcat·Spring·Git 배포)에서 열려 있으면 안 되는 경로를 확인한다."""
import uuid

from dashboard.core import Finding, fetch

META = {
    "id": "sesacedu_exposed_paths",
    "name": "관리·개발 경로 노출",
    "category": "설정 점검",
    "kind": "active",
    "roles": ["user_web", "admin_web", "practice"],  # 이 역할의 대상에서만 보인다
    "attack": [
        {"tactic": "TA0043", "technique": "T1595.003", "name": "Wordlist Scanning"},
        {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
        {"tactic": "TA0006", "technique": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"},
    ],
    "description": "Tomcat 관리 콘솔, Spring Actuator, API 문서, .git·.env 가 밖에서 열리는지 GET 으로만 확인합니다.",
    "params": [],
}

# (경로, 심각도, 제목, 기법, 판정, 조치)
PATHS = [
    ("/.git/HEAD", "high", "Git 저장소 노출", "T1595.003",
     lambda r: r.status == 200 and r.body.startswith("ref:"),
     "배포 디렉터리에서 .git 을 빼거나 웹 서버에서 /.git 접근을 막습니다."),
    ("/.env", "high", "환경변수 파일 노출", "T1552.001",
     lambda r: r.status == 200 and "=" in r.body,
     ".env 를 웹 루트 밖으로 옮기고, 노출됐다면 안의 비밀값을 모두 교체합니다."),
    ("/manager/html", "medium", "Tomcat 관리 콘솔 노출", "T1190",
     lambda r: r.status in (200, 401, 403) and "tomcat" in (r.body + r.header("WWW-Authenticate")).lower(),
     "manager 앱을 지우거나 RemoteAddrValve 로 127.0.0.1 만 허용합니다."),
    ("/host-manager/html", "medium", "Tomcat host-manager 노출", "T1190",
     lambda r: r.status in (200, 401, 403) and "tomcat" in (r.body + r.header("WWW-Authenticate")).lower(),
     "host-manager 앱을 지우거나 127.0.0.1 만 허용합니다."),
    ("/actuator", "medium", "Spring Actuator 노출", "T1190",
     lambda r: r.status == 200 and "_links" in r.body,
     "management.endpoints.web.exposure.include 를 health 정도로 줄이고 관리 포트를 분리합니다."),
    ("/swagger-ui/index.html", "low", "Swagger UI 공개", "T1595.003",
     lambda r: r.status == 200 and "swagger" in r.body.lower(),
     "운영 프로필에서 springdoc.swagger-ui.enabled=false 로 끕니다."),
    ("/v3/api-docs", "low", "OpenAPI 명세 공개", "T1595.003",
     lambda r: r.status == 200 and '"openapi"' in r.body,
     "운영 프로필에서 springdoc.api-docs.enabled=false 로 끕니다."),
]


def run(target, params):
    # SPA 처럼 없는 경로에도 같은 페이지를 주는 경우를 걸러 내려고 기준 응답을 먼저 받는다
    baseline = fetch(f"{target.url}/__dashboard_{uuid.uuid4().hex[:8]}")
    out = []
    for path, sev, title, tech, hit, rec in PATHS:
        r = fetch(target.url + path, record_body=path != "/.env")  # .env 본문은 요청 기록에도 남기지 않는다
        if r.status == 200 and baseline.status == 200 and r.body == baseline.body:
            continue
        if hit(r):
            # 본문은 비밀값이 섞일 수 있어 남기지 않는다
            out.append(Finding(
                title=title, severity=sev, location=r.url, technique=tech, recommendation=rec, response=r,
                evidence=f"GET {r.url} → {r.status}\nContent-Type: {r.header('Content-Type') or '-'}\n본문 {len(r.body)}자(내용 미저장)"))
    return out
