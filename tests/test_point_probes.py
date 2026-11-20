"""취약점별 지점 점검(11-20): ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

가짜 서버를 세워 '받는 구간이 아니면 거기서 끝', '후보면 단계를 올려 가다 확인되면 멈춤' 을 본다.
"""
from html import escape
from urllib.parse import parse_qs, urlsplit

from dashboard import core
from dashboard.core import Point, Response
from modules import sqli_probe, traversal_probe, xss_probe

T = core.Target(id=1, name="t", url="https://sesacedu.store")


def _point(param="q", sample="a"):
    return Point(method="GET", url="https://sesacedu.store/api", param=param, place="query", sample=sample,
                 fields={param: sample})


def _q(url, name):
    return parse_qs(urlsplit(url).query).get(name, [""])[0]


def _server(monkeypatch, handler):
    sent = []

    def fetch(url, **_kw):
        sent.append(url)
        status, body = handler(url)
        return Response(url=url, status=status, body=body)
    monkeypatch.setattr(core, "fetch", fetch)
    return sent


# ── SQL 주입 ─────────────────────────────────────────────────

def test_sqli_not_a_receiving_point_stops_at_screen(monkeypatch):
    sent = _server(monkeypatch, lambda url: (200, "same page"))
    c = sqli_probe.run(T, [_point()], {})[0]
    assert c.verdict == "safe" and "받는 구간이 아님" in c.evidence
    assert len(sent) == 2                                   # 원래 값 + 따옴표, 페이로드는 안 보냄


def test_sqli_boolean_found_in_basic_stage(monkeypatch):
    def handler(url):
        v = _q(url, "q")
        if v.endswith("'"):
            return 500, "error"
        if "'q'='z" in v:
            return 200, "no rows"
        return 200, "row " * 50
    _server(monkeypatch, handler)
    c = sqli_probe.run(T, [_point()], {})[0]
    assert c.verdict == "vuln" and "참·거짓 기반(문자열 자리)" in c.title
    assert "② 기본" in c.evidence and "③ 심화" not in c.evidence


def test_sqli_needs_bypass_when_plain_and_is_filtered(monkeypatch):
    def handler(url):
        v = _q(url, "q")
        if v.endswith("'"):
            return 500, "error"
        if " AND " in v.upper().replace("/**/", " ") and "/**/" not in v:
            return 200, "row " * 50                          # 공백 있는 AND 는 걸러져 늘 같은 결과
        if "/**/" in v and "'q'='z" in v:
            return 200, "no rows"
        return 200, "row " * 50
    _server(monkeypatch, handler)
    c = sqli_probe.run(T, [_point()], {})[0]
    assert c.verdict == "vuln" and "공백 대신 주석" in c.title and "④ 우회" in c.evidence


def test_sqli_error_message_confirms_at_screen(monkeypatch):
    _server(monkeypatch, lambda url: (500, "ORA-00933: SQL command not properly ended")
            if _q(url, "q").endswith("'") else (200, "ok"))
    c = sqli_probe.run(T, [_point()], {})[0]
    assert c.verdict == "vuln" and "Oracle" in c.title and "① 받는 구간" in c.evidence


# ── 경로 조작 ────────────────────────────────────────────────

def test_traversal_found_in_bypass_stage(monkeypatch):
    def handler(url):
        v = _q(url, "file")
        if "....//" in v:
            return 200, "root:x:0:0:root:/root:/bin/bash\n"
        if v == "a.pdf":
            return 200, "%PDF"
        return 404, "not found"
    _server(monkeypatch, handler)
    c = traversal_probe.run(T, [_point("file", "a.pdf")], {"depth": "4"})[0]
    assert c.verdict == "vuln" and "/etc/passwd" in c.title and "④ 우회 ..../ 겹쳐 쓰기" in c.evidence


def test_traversal_skips_points_that_are_not_paths(monkeypatch):
    sent = _server(monkeypatch, lambda url: (200, "list"))
    c = traversal_probe.run(T, [_point("size", "10")], {})[0]
    assert c.verdict == "safe" and "받는 구간이 아님" in c.evidence and len(sent) == 2


# ── XSS ──────────────────────────────────────────────────────

def test_xss_not_reflected_stops_at_screen(monkeypatch):
    sent = _server(monkeypatch, lambda url: (200, "static"))
    c = xss_probe.run(T, [_point()], {})[0]
    assert c.verdict == "safe" and len(sent) == 1


def test_xss_tag_reflected_in_basic(monkeypatch):
    _server(monkeypatch, lambda url: (200, f"<p>{_q(url, 'q')}</p>"))
    c = xss_probe.run(T, [_point()], {})[0]
    assert c.verdict == "vuln" and "② 기본" in c.evidence


def test_xss_escaped_is_potential(monkeypatch):
    _server(monkeypatch, lambda url: (200, f"<p>{escape(_q(url, 'q'))}</p>"))
    c = xss_probe.run(T, [_point()], {})[0]
    assert c.verdict == "potential" and "필터가 있음" in c.evidence


def test_point_modules_are_registered_by_vuln(app):
    from dashboard import routes
    with app.test_request_context():
        mods = routes._modules()
    assert {mods[m].vuln for m in ("sqli_probe", "traversal_probe", "xss_probe")} == {"SQL", "FILE", "XSS"}
    assert all(mods[m].stage == "probe" for m in ("sqli_probe", "traversal_probe", "xss_probe"))


def test_xss_plain_text_payloads_do_not_count_on_safe_pages(monkeypatch):
    """특수문자 없는 값(인코딩 꺾쇠, javascript:)은 걸러져도 그대로 돌아온다 — 그걸로 취약이라 하면 안 된다."""
    _server(monkeypatch, lambda url: (200, f"<p>{escape(_q(url, 'q'))}</p>"))
    c = xss_probe.run(T, [_point()], {})[0]
    assert "④ 우회 javascript: 링크" in c.evidence and c.verdict != "vuln"


def test_xss_javascript_link_counts_only_in_href(monkeypatch):
    _server(monkeypatch, lambda url: (200, f'<a href="{_q(url, "q")}">go</a>') if _q(url, "q").startswith("javascript:")
            else (200, f"<p>{escape(_q(url, 'q'))}</p>"))
    c = xss_probe.run(T, [_point()], {})[0]
    assert c.verdict == "vuln" and "javascript: 링크" in c.evidence


# ── 모듈 팝업(11-20) ─────────────────────────────────────────

def _seed_points(app, client):
    from dashboard.db import get_db
    from tests.test_app import add_target, target_id
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    tid = target_id(app, "https://sesacedu.store")
    client.post("/modules/surface_import/run", data={"target_id": tid,
                "urls": "https://sesacedu.store/backend/lectures?keyword=a&size=10"}, follow_redirects=True)
    return tid


def test_probe_module_panel_shows_settings_and_collected_points(app, client):
    tid = _seed_points(app, client)
    html = client.get(f"/modules/sqli_probe/panel?target={tid}&partial=1").get_data(as_text=True)
    assert "<html" not in html                                        # 조각만
    assert 'id="mp-form"' in html and 'action="/surface/probe"' in html
    assert 'name="module_id" value="sqli_probe"' in html
    assert 'value="/modules?target=%d&amp;open=sqli_probe"' % tid in html   # 실행 뒤 같은 팝업으로
    assert html.count('form="mp-form"') >= 2 and "keyword" in html and "① 받는 구간" in html


def test_target_module_panel_has_no_point_table(app, client):
    tid = _seed_points(app, client)
    html = client.get(f"/modules/http_security_headers/panel?target={tid}&partial=1").get_data(as_text=True)
    assert 'action="/modules/http_security_headers/run"' in html and 'class="mp-surface"' not in html


def test_probe_run_from_panel_comes_back_to_the_panel(app, client, monkeypatch):
    from dashboard.core import Response
    tid = _seed_points(app, client)
    monkeypatch.setattr(core, "fetch", lambda url, **kw: Response(url=url, status=200, body="same"))
    with app.app_context():
        from dashboard.db import get_db
        pid = get_db().execute("SELECT id FROM points WHERE param = 'keyword'").fetchone()["id"]
    r = client.post("/surface/probe", data={"target_id": tid, "module_id": "sqli_probe", "point": pid,
                                            "confirm": "yes", "sqli_probe__methods": "GET",
                                            "back": f"/modules?target={tid}&open=sqli_probe"})
    assert r.headers["Location"].endswith(f"/modules?target={tid}&open=sqli_probe")
    # 바깥 주소로는 돌려보내지 않는다
    r = client.post("/surface/probe", data={"target_id": tid, "module_id": "sqli_probe", "point": pid,
                                            "confirm": "yes", "back": "//evil.example/x"})
    assert "evil.example" not in r.headers["Location"]


def test_modules_page_cards_open_the_panel(app, client):
    tid = _seed_points(app, client)
    html = client.get(f"/modules?target={tid}&open=xss_probe").get_data(as_text=True)
    assert f'data-panel="/modules/xss_probe/panel?target={tid}&amp;partial=1"' in html
    assert 'id="mod-dialog"' in html and 'data-open="xss_probe"' in html


def test_cards_do_not_reopen_from_memory():
    """펼친 카드를 기억해 다시 펴면, 카드를 눌러도 팝업만 열리고 접히지 않았다(사용자 지적 11-20)."""
    from pathlib import Path
    js = (Path(__file__).resolve().parent.parent / "dashboard/static/app.js").read_text(encoding="utf-8")
    assert 'localStorage.removeItem("modOpen")' in js
    assert 'localStorage.setItem("modOpen"' not in js and "if (open[card.dataset.mod]) set(card, true" not in js


def test_panel_has_select_all_boxes(app, client):
    tid = _seed_points(app, client)
    html = client.get(f"/modules/sqli_probe/panel?target={tid}&partial=1").get_data(as_text=True)
    assert 'class="mp-all"' in html and 'class="mp-group"' in html


# ── 실행해도 화면을 넘기지 않는다(11-20) ─────────────────────────

FETCH = {"X-Requested-With": "fetch"}


def test_background_run_answers_json_instead_of_redirect(app, client, monkeypatch):
    from dashboard.core import Response
    tid = _seed_points(app, client)
    monkeypatch.setattr(core, "fetch", lambda url, **kw: Response(url=url, status=200, body="same"))
    with app.app_context():
        from dashboard.db import get_db
        pid = get_db().execute("SELECT id FROM points WHERE param = 'keyword'").fetchone()["id"]
    r = client.post("/surface/probe", headers=FETCH, data={"target_id": tid, "module_id": "sqli_probe", "point": pid,
                                                           "confirm": "yes", "sqli_probe__methods": "GET"})
    assert r.status_code == 200 and r.is_json and r.json["ok"] is True


def test_background_run_error_comes_back_as_message(app, client):
    tid = _seed_points(app, client)
    r = client.post("/surface/probe", headers=FETCH, data={"target_id": tid, "module_id": "sqli_probe"})
    assert r.json["ok"] is False and any("지점을 고르세요" in m["message"] for m in r.json["messages"])
    # 화면에서 보낸 것이 아니면(fetch 표시 없음) 예전처럼 넘긴다
    r = client.post("/surface/probe", data={"target_id": tid, "module_id": "sqli_probe"})
    assert r.status_code == 302


def test_jobs_poll_hands_over_finished_runs_once(app, client, monkeypatch):
    from dashboard.core import Response
    tid = _seed_points(app, client)
    monkeypatch.setattr(core, "fetch", lambda url, **kw: Response(url=url, status=200, body="same"))
    with app.app_context():
        from dashboard.db import get_db
        pid = get_db().execute("SELECT id FROM points WHERE param = 'keyword'").fetchone()["id"]
    client.post("/surface/probe", headers=FETCH, data={"target_id": tid, "module_id": "sqli_probe", "point": pid,
                                                       "confirm": "yes", "sqli_probe__methods": "GET"})
    first = client.get(f"/jobs?target={tid}").json["done"]
    assert [j["module_id"] for j in first] == ["sqli_probe"]
    assert client.get(f"/jobs?target={tid}").json["done"] == []      # 한 번만 알린다
