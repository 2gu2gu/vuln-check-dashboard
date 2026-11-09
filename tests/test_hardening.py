"""요청 기록·인증 헤더·요청 한도·자기 점검 차단·CSRF·Host 검사."""
import email.message
import json
import re
import urllib.error

import pytest
from flask import g

from dashboard import core, create_app
from dashboard.core import BudgetExceeded, RunContext
from dashboard.db import get_db


class FakeResp:
    def __init__(self, status=200, headers=(("Content-Type", "text/html; charset=utf-8"),), body=b"<p>ok</p>"):
        self.status = status
        self.headers = email.message.Message()
        for k, v in headers:
            self.headers[k] = v
        self._body = body

    def read(self, _n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


@pytest.fixture
def opener(monkeypatch):
    """실제 네트워크 대신 응답을 돌려주고, 보낸 요청을 모아 둔다."""
    sent, reply = [], {"resp": FakeResp()}

    def open_(req, timeout=10):
        sent.append(req)
        if isinstance(reply["resp"], Exception):
            raise reply["resp"]
        return reply["resp"]
    monkeypatch.setattr(core._opener, "open", open_)
    return sent, reply


def add_target(client, url="https://sesacedu.store", project="sesacedu", role="user_web"):
    return client.post("/targets", data={"project": project, "role": role, "name": "웹", "url": url},
                       follow_redirects=True)


def test_join():
    assert core.join("http://a:1", "x") == "http://a:1/x"
    assert core.join("http://a:1/", "/x") == "http://a:1/x"


def test_exchange_recorded_whole(app, client, opener):
    """보낸 것·받은 것을 가리지 않고 남긴다(2026-11-07 사용자 지시)."""
    sent, reply = opener
    add_target(client)
    client.post("/targets/1/headers", data={"headers": "Cookie: SID=abc123\nAuthorization: Bearer tok999"})
    reply["resp"] = FakeResp(headers=[("Content-Type", "text/html"), ("Set-Cookie", "JSESSIONID=SERVERSECRET; Path=/")])
    page = client.post("/modules/http_security_headers/run", data={"target_id": 1, "path": "courses"},
                       follow_redirects=True).get_data(as_text=True)
    assert "요청 1개" in page
    # 실제로는 인증 헤더가 나갔고, 경로는 / 가 없어도 붙었다
    assert sent[0].full_url == "https://sesacedu.store/courses"
    assert sent[0].get_header("Cookie") == "SID=abc123"
    with app.app_context():
        x = get_db().execute("SELECT * FROM exchanges").fetchone()
        f = get_db().execute("SELECT exchange_id FROM findings LIMIT 1").fetchone()
    stored = x["req_headers"] + x["resp_headers"]
    assert "abc123" in stored and "tok999" in stored and "SERVERSECRET" in stored
    assert "***" not in stored
    assert f["exchange_id"] == x["id"]

    detail = client.get(f"/history/{x['id']}").get_data(as_text=True)
    assert "GET /courses HTTP/1.1" in detail and "Host: sesacedu.store" in detail
    assert "/courses" in client.get("/history?target=1").get_data(as_text=True)
    report = json.loads(client.get("/report/1.json").get_data(as_text=True))
    assert report["findings"][0]["exchange"]["request"].startswith("GET /courses")
    assert "GET /courses HTTP/1.1" in client.get("/report/1.md").get_data(as_text=True)


def test_auth_headers_only_to_target_host(app, opener):
    sent, _ = opener
    with app.test_request_context():
        g.scope_hosts = ["sesacedu.store", "localhost"]
        g.run_ctx = RunContext("https://sesacedu.store", {"Cookie": "SID=x"})
        core.fetch("https://sesacedu.store/a")
        core.fetch("http://localhost:3000/b")
    assert sent[0].get_header("Cookie") == "SID=x"
    assert sent[1].get_header("Cookie") is None


def test_request_budget(app, opener):
    with app.test_request_context():
        g.scope_hosts = ["sesacedu.store"]
        g.run_ctx = RunContext("https://sesacedu.store", max_requests=2)
        core.fetch("https://sesacedu.store/1")
        core.fetch("https://sesacedu.store/2")
        with pytest.raises(BudgetExceeded):
            core.fetch("https://sesacedu.store/3")
    assert len(opener[0]) == 2


def test_connection_error_is_recorded(app, client, opener):
    _, reply = opener
    add_target(client)
    reply["resp"] = urllib.error.URLError("connection refused")
    page = client.post("/modules/http_security_headers/run", data={"target_id": 1, "path": "/"},
                       follow_redirects=True).get_data(as_text=True)
    assert "실패" in page
    with app.app_context():
        x = get_db().execute("SELECT status, error FROM exchanges").fetchone()
        run = get_db().execute("SELECT status FROM runs").fetchone()
    assert x["status"] == 0 and "refused" in x["error"] and run["status"] == "error"


def test_every_response_body_is_recorded(app, client, opener):
    """.env 본문도 그대로 남는다 — 무엇이 읽혔는지가 증거다."""
    _, reply = opener
    add_target(client)
    reply["resp"] = FakeResp(body=b"DB_PASSWORD=supersecret\n")
    client.post("/modules/sesacedu_exposed_paths/run", data={"target_id": 1, "confirm": "yes"})
    with app.app_context():
        bodies = " ".join(r["resp_body"] for r in get_db().execute("SELECT resp_body FROM exchanges WHERE url LIKE '%/.env'"))
    assert "supersecret" in bodies and "남기지 않음" not in bodies


def test_self_scan_blocked(client):
    assert "대시보드 자신" in add_target(client, "http://127.0.0.1:5050", "general", "").get_data(as_text=True)
    assert "등록했습니다" in add_target(client, "http://127.0.0.1:5051", "general", "").get_data(as_text=True)


def test_int_param_validated(client, opener):
    add_target(client)
    page = client.post("/modules/surface_crawl/run", data={"target_id": 1, "max_pages": "abc"},
                       follow_redirects=True).get_data(as_text=True)
    assert "숫자를" in page and opener[0] == []


def test_csrf_and_host(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "t", "DATABASE": str(tmp_path / "c.sqlite3"), "DELAY_MS": 0})
    c = app.test_client()
    data = {"project": "general", "name": "로컬", "url": "http://127.0.0.1:9"}
    assert c.post("/targets", data=data).status_code == 400
    token = re.search(r'name="_csrf" value="([0-9a-f]+)"', c.get("/targets").get_data(as_text=True)).group(1)
    assert c.post("/targets", data={**data, "_csrf": token}).status_code == 302
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 400


def _app(tmp_path, **cfg):
    return create_app({"TESTING": True, "SECRET_KEY": "t", "DATABASE": str(tmp_path / "h.sqlite3"),
                       "CSRF": False, "DELAY_MS": 0, **cfg})


def test_allowed_hosts_opens_one_name(tmp_path):
    """서버에 올려 밖에서 열 때는 들어올 이름을 적어 준다. 적은 것만 들어온다."""
    c = _app(tmp_path, ALLOWED_HOSTS=["dast.example"]).test_client()
    assert c.get("/", headers={"Host": "dast.example"}).status_code == 200
    assert c.get("/", headers={"Host": "dast.example:80"}).status_code == 200   # 포트는 떼고 본다
    assert c.get("/", headers={"Host": "DAST.EXAMPLE"}).status_code == 200      # 대소문자 무시
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert c.get("/", headers={"Host": "127.0.0.1"}).status_code == 200         # 로컬은 늘 된다


def test_allowed_hosts_star_takes_any(tmp_path):
    """공인 IP 가 중지·시작마다 바뀌는 자리용. 이름 검사를 통째로 끄는 것과 같다."""
    c = _app(tmp_path, ALLOWED_HOSTS=["*"]).test_client()
    assert c.get("/", headers={"Host": "13.125.1.2"}).status_code == 200
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 200


def test_default_is_local_only(tmp_path):
    """기본값은 그대로다 — 적지 않으면 내 PC 뿐."""
    c = _app(tmp_path).test_client()
    assert c.get("/", headers={"Host": "localhost"}).status_code == 200
    assert c.get("/", headers={"Host": "dast.example"}).status_code == 400
