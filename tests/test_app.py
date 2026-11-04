from dashboard import core
from dashboard.db import get_db
from modules import http_security_headers
from projects.sesacedu.modules import exposed_paths


def add_target(client, url, project="sesacedu", name="웹", role="user_web"):
    return client.post("/targets", data={"project": project, "role": role, "name": name, "url": url},
                       follow_redirects=True)


def target_id(app, url):
    with app.app_context():
        return get_db().execute("SELECT id FROM targets WHERE url = ?", [url]).fetchone()["id"]


def test_pages_render_empty(client):
    for path in ("/", "/targets", "/modules", "/surface", "/attack", "/scenario", "/help"):
        assert client.get(path).status_code == 200, path


def test_help_link_points_to_current_screen(client):
    page = client.get("/modules").get_data(as_text=True)
    assert "/help#modules" in page
    assert 'id="modules"' in client.get("/help").get_data(as_text=True)


def test_target_scope_per_project(client):
    assert "등록했습니다" in add_target(client, "https://sesacedu.store").get_data(as_text=True)
    # 범용 프로젝트 범위(localhost)에는 sesacedu.store 가 없다
    assert "허용 범위 밖" in add_target(client, "https://www.sesacedu.store", project="general", role="").get_data(as_text=True)
    assert "허용 범위 밖" in add_target(client, "https://example.com").get_data(as_text=True)


def test_run_passive_module_and_flow(app, client, monkeypatch, fake_fetch):
    add_target(client, "https://sesacedu.store")
    tid = target_id(app, "https://sesacedu.store")
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    page = client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"},
                       follow_redirects=True).get_data(as_text=True)
    assert "HSTS 헤더 없음" in page

    with app.app_context():
        fid = get_db().execute("SELECT id FROM findings WHERE title = 'HSTS 헤더 없음'").fetchone()["id"]
    client.post(f"/findings/{fid}/status", data={"status": "confirmed"})
    with app.app_context():
        assert get_db().execute("SELECT status FROM findings WHERE id = ?", [fid]).fetchone()["status"] == "confirmed"

    assert "T1595.002" in client.get(f"/attack?target={tid}").get_data(as_text=True)
    assert "정찰" in client.get(f"/scenario?target={tid}").get_data(as_text=True)
    report = client.get(f"/report/{tid}.md")
    assert report.status_code == 200 and "HSTS 헤더 없음" in report.get_data(as_text=True)


def test_active_module_needs_confirm(app, client, monkeypatch, fake_fetch):
    add_target(client, "https://sesacedu.store")
    tid = target_id(app, "https://sesacedu.store")
    f = fake_fetch({})
    monkeypatch.setattr(exposed_paths, "fetch", f)
    page = client.post("/modules/sesacedu_exposed_paths/run", data={"target_id": tid},
                       follow_redirects=True).get_data(as_text=True)
    assert "체크해야" in page and f.calls == []
    client.post("/modules/sesacedu_exposed_paths/run", data={"target_id": tid, "confirm": "yes"})
    assert f.calls


def test_project_module_blocked_on_other_project(app, client):
    add_target(client, "http://127.0.0.1:9", project="general", name="로컬", role="")
    tid = target_id(app, "http://127.0.0.1:9")
    page = client.post("/modules/sesacedu_exposed_paths/run", data={"target_id": tid, "confirm": "yes"},
                       follow_redirects=True).get_data(as_text=True)
    assert "전용 모듈" in page
    assert "관리·개발 경로 노출" not in client.get(f"/modules?target={tid}").get_data(as_text=True)


def test_module_cannot_leave_project_scope(app, client, monkeypatch):
    """모듈이 엉뚱한 주소로 요청하면 실행 중 범위로 막히고 실패로 기록된다."""
    add_target(client, "https://sesacedu.store")
    tid = target_id(app, "https://sesacedu.store")
    monkeypatch.setattr(http_security_headers, "fetch", lambda url, **k: core.fetch("https://example.com/"))
    page = client.post("/modules/http_security_headers/run", data={"target_id": tid},
                       follow_redirects=True).get_data(as_text=True)
    assert "허용 범위 밖" in page
    with app.app_context():
        assert get_db().execute("SELECT status FROM runs").fetchone()["status"] == "error"


# ── 기본 화면은 밝게 (데스크톱 설정을 따르지 않는다) ─────────────────
# 점검 화면은 발표·캡처에 그대로 들어가므로 기본을 한 가지로 고정한다.
# 어두운 화면은 위쪽 버튼으로 켤 때만 쓴다.

def test_dark_theme_only_when_asked():
    from pathlib import Path
    css = (Path(__file__).resolve().parent.parent / "dashboard/static/style.css").read_text(encoding="utf-8")
    assert "prefers-color-scheme" not in css, "데스크톱 설정을 따라가면 기본이 밝은 화면이 아니게 된다"
    assert ':root[data-theme="dark"]' in css

    js = (Path(__file__).resolve().parent.parent / "dashboard/static/app.js").read_text(encoding="utf-8")
    assert "prefers-color-scheme" not in js
