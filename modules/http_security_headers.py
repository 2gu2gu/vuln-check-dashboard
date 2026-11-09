"""HTTP 보안 헤더·쿠키 속성 점검. 페이지 하나의 응답 헤더만 읽는다."""
from dashboard.core import Finding, fetch, join

META = {
    "id": "http_security_headers",
    "name": "HTTP 보안 헤더",
    "category": "설정 점검",
    "kind": "passive",
    "attack": [
        {"tactic": "TA0043", "technique": "T1595.002", "name": "Vulnerability Scanning"},
        {"tactic": "TA0006", "technique": "T1539", "name": "Steal Web Session Cookie"},
    ],
    "description": "응답의 보안 헤더(HSTS·CSP·nosniff·클릭재킹 방어·Referrer-Policy)와 쿠키 속성(Secure·HttpOnly·SameSite)을 봅니다.",
    "params": [{"name": "path", "need": "optional", "label": "경로", "default": "/"}],
}

# (헤더, 심각도, 제목, 조치, HTTPS 에서만 의미 있음)
HEADERS = [
    ("Strict-Transport-Security", "medium", "HSTS 헤더 없음",
     "HTTPS 응답에 Strict-Transport-Security: max-age=31536000; includeSubDomains 를 붙입니다.", True),
    ("Content-Security-Policy", "medium", "CSP 헤더 없음",
     "Content-Security-Policy 로 스크립트 출처를 제한합니다. 처음엔 Report-Only 로 시작해도 됩니다.", False),
    ("X-Content-Type-Options", "low", "X-Content-Type-Options 없음",
     "X-Content-Type-Options: nosniff 를 붙입니다.", False),
    ("Referrer-Policy", "low", "Referrer-Policy 없음",
     "Referrer-Policy: strict-origin-when-cross-origin 을 붙입니다.", False),
]


def run(target, params):
    r = fetch(join(target.url, params.get("path") or "/"))
    https = r.url.startswith("https://")
    status_line = f"GET {r.url} → {r.status}"
    out = []

    for name, sev, title, rec, https_only in HEADERS:
        if https_only and not https:
            continue
        if not r.header(name):
            out.append(Finding(title=title, severity=sev, location=r.url,
                               evidence=f"{status_line}\n{name}: (없음)", recommendation=rec, response=r))

    csp = r.header("Content-Security-Policy").lower()
    if not r.header("X-Frame-Options") and "frame-ancestors" not in csp:
        out.append(Finding(
            title="클릭재킹 방어 헤더 없음", severity="medium", location=r.url,
            evidence=f"{status_line}\nX-Frame-Options: (없음)\nCSP frame-ancestors: (없음)",
            recommendation="X-Frame-Options: DENY 또는 CSP frame-ancestors 'none' 을 붙입니다.", response=r))

    for raw in r.header_all("Set-Cookie"):
        cookie_name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            missing.append("SameSite")
        if missing:
            out.append(Finding(
                title=f"쿠키 속성 누락: {cookie_name}", severity="low", location=r.url,
                evidence=f"{status_line}\nSet-Cookie: {raw}\n누락: {', '.join(missing)}",
                recommendation=f"{cookie_name} 쿠키에 {', '.join(missing)} 속성을 붙입니다.",
                technique="T1539", response=r))
    return out
