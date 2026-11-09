from dashboard.core import Target
from modules import http_security_headers, tech_fingerprint
from projects.sesacedu.modules import exposed_paths

T = Target(1, "t", "https://sesacedu.store")


def titles(findings):
    return {f.title for f in findings}


def test_headers_missing(monkeypatch, fake_fetch):
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {"headers": [
        ("Set-Cookie", "JSESSIONID=SECRETVALUE; Path=/"),
    ]}}))
    out = http_security_headers.run(T, {"path": "/"})
    assert {"HSTS 헤더 없음", "CSP 헤더 없음", "클릭재킹 방어 헤더 없음", "쿠키 속성 누락: JSESSIONID"} <= titles(out)
    cookie = next(f for f in out if f.title.startswith("쿠키"))
    assert "SECRETVALUE" in cookie.evidence      # 가리지 않는다 — 값까지 그대로
    assert cookie.technique == "T1539"


def test_headers_all_present(monkeypatch, fake_fetch):
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {"headers": [
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
        ("Set-Cookie", "SID=x; Secure; HttpOnly; SameSite=Lax"),
    ]}}))
    assert http_security_headers.run(T, {"path": "/"}) == []


def test_fingerprint(monkeypatch, fake_fetch):
    monkeypatch.setattr(tech_fingerprint, "fetch", fake_fetch({
        "store/": {"headers": [("Server", "Apache Tomcat/10.1.20")]},
    }))
    # 없는 경로는 fake_fetch 기본 404 → 본문에 버전 없음
    out = tech_fingerprint.run(T, {})
    assert titles(out) == {"Server 헤더에 버전 노출"}


def test_fingerprint_error_page(monkeypatch, fake_fetch):
    f = fake_fetch({"store/": {}})
    body = "<h3>Apache Tomcat/10.1.20</h3> java.lang.NullPointerException\n at org.sesac.Foo.bar(Foo.java:1)"
    orig = f

    def fetch(url, **kw):
        r = orig(url, **kw)
        if "__dashboard_" in url:
            r.status, r.body = 500, body
        return r
    monkeypatch.setattr(tech_fingerprint, "fetch", fetch)
    assert {"오류 페이지에 서버 버전 노출", "오류 페이지에 스택 트레이스 노출"} <= titles(tech_fingerprint.run(T, {}))


def test_exposed_paths(monkeypatch, fake_fetch):
    monkeypatch.setattr(exposed_paths, "fetch", fake_fetch({
        "/.git/HEAD": {"body": "ref: refs/heads/main\n"},
        "/.env": {"body": "DB_PASSWORD=supersecret\n"},
        "/manager/html": {"status": 401, "headers": [("WWW-Authenticate", 'Basic realm="Tomcat Manager Application"')]},
    }))
    out = exposed_paths.run(T, {})
    assert titles(out) == {"Git 저장소 노출", "환경변수 파일 노출", "Tomcat 관리 콘솔 노출"}
    assert any("supersecret" in f.evidence for f in out)   # 근거에 본문이 들어간다


def test_exposed_paths_spa_fallback(monkeypatch, fake_fetch):
    # 모든 경로에 같은 index.html 을 주는 SPA 는 오탐하지 않는다
    spa = {"body": "ref: <html>app</html>"}

    def fetch(url, **_kw):
        from dashboard.core import Response
        return Response(url=url, status=200, headers=[], body=spa["body"])
    monkeypatch.setattr(exposed_paths, "fetch", fetch)
    assert exposed_paths.run(T, {}) == []
