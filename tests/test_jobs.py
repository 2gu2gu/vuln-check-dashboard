"""모듈을 뒤에서 돌린다 — 바로 돌아오고, 여러 개를 같이 돌리고, 멈출 수 있다."""
import email.message
import threading
import time

import pytest

from dashboard import core, jobs
from dashboard.db import get_db
from modules import http_security_headers


def add_target(client, url="https://sesacedu.store"):
    return client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹", "url": url},
                       follow_redirects=True)


def only_target(app):
    with app.app_context():
        return get_db().execute("SELECT id FROM targets").fetchone()["id"]


class _Resp:
    """urllib 이 돌려주는 모양 — 헤더는 email.message.Message 라야 한다."""
    status = 200
    url = "https://sesacedu.store/"

    def __init__(self):
        self.headers = email.message.Message()
        self.headers["Content-Type"] = "text/html; charset=utf-8"

    def read(self, _n=-1):
        return b"<html>ok</html>"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


@pytest.fixture
def real_http(monkeypatch):
    """core.fetch 를 그대로 지나게 하고 소켓만 가짜로. 요청 수·기록이 쌓인다."""
    monkeypatch.setattr(core._opener, "open", lambda req, timeout=10: _Resp())


def slow_fetch(seconds=0.05, gate=None):
    """한 요청에 시간이 걸리는 fetch. 멈춤·동시 실행을 보려고 쓴다."""
    def fetch(url, **_kw):
        if gate is not None:
            gate.wait(timeout=5)
        time.sleep(seconds)
        return core.Response(url=url, status=200, headers=[], body="x")
    return fetch


# ── 바로 돌아온다 ──────────────────────────────────────────────

def test_run_returns_before_the_module_finishes(app, monkeypatch):
    """요청이 모듈을 기다리지 않는다. 기다리면 긴 모듈 동안 화면이 멈춘다."""
    gate = threading.Event()
    monkeypatch.setattr(http_security_headers, "fetch", slow_fetch(gate=gate))
    client = app.test_client()          # 기다려 주는 래퍼를 쓰지 않는다
    add_target(client)
    tid = only_target(app)

    start = time.time()
    r = client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    assert r.status_code in (302, 303)
    assert time.time() - start < 2          # 모듈은 아직 gate 에 막혀 있다
    assert jobs.live_count() == 1

    gate.set()
    assert jobs.wait_all(timeout=10)
    assert jobs.live_count() == 0


def test_result_shows_up_on_the_next_page(app, client, monkeypatch, fake_fetch):
    """작업자는 flash 를 못 쓴다(요청이 없다). 결과 문구가 어디에도 안 남으면 안 된다."""
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    page = client.get(f"/?target={tid}").get_data(as_text=True)
    assert "건 발견" in page and "요청" in page


def test_run_is_written_to_the_log(app, client, monkeypatch, fake_fetch):
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    with app.app_context():
        run = get_db().execute("SELECT status, message FROM runs ORDER BY id DESC").fetchone()
    assert run["status"] == "done" and "발견" in run["message"]


def test_requests_are_counted_and_recorded(app, client, monkeypatch, real_http):
    """요청 수와 요청 기록은 core.fetch 를 지날 때만 쌓인다."""
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    with app.app_context():
        run = get_db().execute("SELECT id, sent FROM runs ORDER BY id DESC").fetchone()
        n = get_db().execute("SELECT COUNT(*) FROM exchanges WHERE run_id = ?", [run["id"]]).fetchone()[0]
    assert run["sent"] >= 1 and n >= 1


# ── 여러 개 동시에 ─────────────────────────────────────────────

def test_several_modules_run_at_once(app, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(http_security_headers, "fetch", slow_fetch(gate=gate))
    client = app.test_client()
    add_target(client)
    tid = only_target(app)
    for _ in range(3):
        client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    assert jobs.live_count() == 3
    gate.set()
    assert jobs.wait_all(timeout=10)


def test_too_many_at_once_is_refused(app, monkeypatch):
    """같은 서버를 여러 모듈이 동시에 때리면 합쳐진 요청량이 그만큼 늘어난다."""
    gate = threading.Event()
    monkeypatch.setattr(http_security_headers, "fetch", slow_fetch(gate=gate))
    client = app.test_client()
    add_target(client)
    tid = only_target(app)
    for _ in range(jobs.MAX_LIVE):
        client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    assert jobs.live_count() == jobs.MAX_LIVE

    page = client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"},
                       follow_redirects=True).get_data(as_text=True)
    assert f"지금 {jobs.MAX_LIVE}개가 돌고 있습니다" in page
    assert jobs.live_count() == jobs.MAX_LIVE      # 늘지 않았다
    gate.set()
    assert jobs.wait_all(timeout=10)


# ── 멈춤 ──────────────────────────────────────────────────────

def test_cancel_stops_before_the_next_request(app, monkeypatch):
    """이미 나간 요청은 되돌릴 수 없다 — 보내기 직전에만 멈춘다."""
    monkeypatch.setattr(http_security_headers, "fetch", slow_fetch(seconds=0.08))
    client = app.test_client()
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})

    run_id = jobs.listing()[0]["run_id"]
    assert client.post(f"/jobs/{run_id}/cancel").get_json()["ok"] is True
    assert jobs.wait_all(timeout=10)
    assert jobs.get(run_id).status == "cancelled"
    with app.app_context():
        assert get_db().execute("SELECT status FROM runs WHERE id = ?", [run_id]).fetchone()[0] == "cancelled"


def test_cancelling_a_finished_run_says_so(app, client, monkeypatch, fake_fetch):
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    run_id = jobs.listing()[0]["run_id"]
    r = client.post(f"/jobs/{run_id}/cancel")
    assert r.status_code == 404 and r.get_json()["ok"] is False


# ── 드로어가 보는 것 ───────────────────────────────────────────

def test_jobs_endpoint(app, client, monkeypatch, fake_fetch):
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    d = client.get(f"/jobs?target={tid}").get_json()
    assert d["max"] == jobs.MAX_LIVE and len(d["jobs"]) == 1
    one = d["jobs"][0]
    assert one["module"] == "HTTP 보안 헤더" and one["status"] == "done" and one["live"] is False


def test_exchanges_stream_for_one_run(app, client, monkeypatch, real_http):
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    run_id = jobs.listing()[0]["run_id"]
    d = client.get(f"/jobs/{run_id}/exchanges").get_json()
    assert d["exchanges"] and d["live"] is False
    # after 를 주면 그 뒤만 — 화면이 쌓인 것을 다시 받지 않는다
    last = d["exchanges"][-1]["id"]
    assert client.get(f"/jobs/{run_id}/exchanges?after={last}").get_json()["exchanges"] == []


def test_drawer_is_on_every_page(client):
    html = client.get("/").get_data(as_text=True)
    assert 'id="jobs-drawer"' in html and 'id="jobs-open"' in html


# ── 안전장치가 백그라운드에서도 선다 ────────────────────────────

def test_scope_still_blocks_in_the_worker(app, monkeypatch):
    """범위 검사는 요청 컨텍스트(g)에 있었다. 스레드에서도 서야 한다."""
    sent = []
    monkeypatch.setattr(core._opener, "open", lambda *a, **k: sent.append(a))
    monkeypatch.setattr(http_security_headers, "fetch",
                        lambda url, **k: core.fetch("https://example.com/"))
    client = app.test_client()
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    assert jobs.wait_all(timeout=10)
    job = jobs.listing()[0]
    assert job["status"] == "error" and "허용 범위 밖" in job["error"]
    assert sent == []          # 보내기 전에 막혔다


def test_budget_still_applies_in_the_worker(app, monkeypatch):
    app.config["MAX_REQUESTS"] = 2
    monkeypatch.setattr(http_security_headers, "fetch",
                        lambda url, **k: core.fetch("https://sesacedu.store/"))
    monkeypatch.setattr(core._opener, "open", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("보냄")))
    client = app.test_client()
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    assert jobs.wait_all(timeout=10)
    with app.app_context():
        assert get_db().execute("SELECT status FROM runs ORDER BY id DESC").fetchone()[0] == "error"


# ── 알림은 한 번만 ────────────────────────────────────────────
# 전에는 화면을 그릴 때마다 끝난 작업을 전부 다시 그렸다. 새로고침할수록
# 쌓여서 화면을 가렸다(사용자 지적 11-04).

def test_a_finished_run_is_announced_once(app, client, monkeypatch, fake_fetch):
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})

    first = client.get(f"/?target={tid}").get_data(as_text=True)
    assert first.count('role="status"') == 1
    again = client.get(f"/?target={tid}").get_data(as_text=True)
    assert 'role="status"' not in again         # 두 번째 화면에는 안 뜬다


def test_failures_are_kept_until_closed(app, client, monkeypatch):
    """실패는 읽어야 한다 — 저절로 사라지지 않게 표시해 둔다."""
    monkeypatch.setattr(http_security_headers, "fetch",
                        lambda url, **k: core.fetch("https://example.com/"))
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    page = client.get(f"/?target={tid}").get_data(as_text=True)
    assert 'data-keep="yes"' in page and "toast error" in page


def test_the_record_stays_in_the_drawer(app, client, monkeypatch, fake_fetch):
    """알림은 사라져도 기록은 남는다."""
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    add_target(client)
    tid = only_target(app)
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    client.get(f"/?target={tid}")               # 한 번 알리고 지나간다
    assert len(client.get(f"/jobs?target={tid}").get_json()["jobs"]) == 1
