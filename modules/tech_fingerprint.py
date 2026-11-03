"""서버·프레임워크 정보 노출 점검. 첫 페이지와 없는 경로 하나의 응답을 읽는다."""
import re
import uuid

from dashboard.core import Finding, fetch

META = {
    "id": "tech_fingerprint",
    "name": "서버 정보 노출",
    "category": "정보 수집",
    "kind": "passive",
    "attack": [{"tactic": "TA0043", "technique": "T1592.002", "name": "Gather Victim Host Information: Software"}],
    "description": "Server·X-Powered-By 헤더, generator 메타 태그, 오류 페이지의 버전·스택 트레이스 노출을 봅니다.",
    "params": [],
}

VERSION = re.compile(r"\d+\.\d+")
ERROR_PAGE_VERSION = re.compile(r"(Apache Tomcat|nginx|Apache|Jetty|Microsoft-IIS|Express)[/ ]v?(\d+(?:\.\d+)+)", re.I)
STACK_TRACE = re.compile(r"(java\.lang\.\w+(Exception|Error)|\bat (org|com|java)\.[\w.$]+\(|Traceback \(most recent call last\))")
GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

HIDE = "응답 헤더에서 제품명·버전을 지웁니다(예: nginx server_tokens off, Tomcat server 속성)."


def run(target, params):
    out = []
    home = fetch(target.url + "/")
    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = home.header(name)
        if val:
            has_ver = bool(VERSION.search(val))
            out.append(Finding(
                title=f"{name} 헤더에 {'버전' if has_ver else '제품명'} 노출", severity="low" if has_ver else "info",
                location=home.url, evidence=f"GET {home.url} → {home.status}\n{name}: {val}", recommendation=HIDE,
                response=home))
    m = GENERATOR.search(home.body)
    if m:
        out.append(Finding(title="generator 메타 태그 노출", severity="info", location=home.url,
                           evidence=f'<meta name="generator" content="{m.group(1)}">',
                           recommendation="generator 메타 태그를 지웁니다.", response=home))

    # 없는 경로로 기본 오류 페이지를 띄워 본다
    miss = fetch(f"{target.url}/__dashboard_{uuid.uuid4().hex[:8]}")
    m = ERROR_PAGE_VERSION.search(miss.body)
    if m:
        out.append(Finding(title="오류 페이지에 서버 버전 노출", severity="low", location=miss.url,
                           evidence=f"GET {miss.url} → {miss.status}\n본문: …{m.group(0)}…",
                           recommendation="기본 오류 페이지 대신 사용자 정의 오류 페이지를 씁니다.", response=miss))
    m = STACK_TRACE.search(miss.body)
    if m:
        out.append(Finding(title="오류 페이지에 스택 트레이스 노출", severity="medium", location=miss.url,
                           evidence=f"GET {miss.url} → {miss.status}\n본문: …{m.group(0)}…",
                           recommendation="운영 환경에서 예외 상세를 응답에 싣지 않도록 오류 처리기를 둡니다.", response=miss))
    return out
