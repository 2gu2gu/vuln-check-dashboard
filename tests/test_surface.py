from urllib.parse import parse_qsl, urlsplit

import pytest

from dashboard import core, probe
from dashboard.core import Point, Response, Target
from dashboard.db import get_db
from modules import reflection_check, surface_crawl, surface_import

T = Target(1, "t", "https://sesacedu.store")

HOME = """<html><body>
<a href="/courses?category=web&level=1">강의</a>
<a href="https://evil.example/x?a=1">밖</a>
<a href="/logout">로그아웃</a>
<a href="/img/a.png">그림</a>
<form action="/search" method="get"><input name="keyword" value="sql"><input type="submit" value="찾기"></form>
<form action="/qna?board=1" method="post"><input name="title"><textarea name="body"></textarea><input type="hidden" name="csrf" value="SECRET1"></form>
<script src="/assets/app.js"></script>
<script>fetch('/api/inline/ping?x=1')</script>
</body></html>"""
APP_JS = 'const u = "/api/lectures?keyword=" + k; axios.get(`/api/lectures/${id}/materials`); "/notapi/x"'


def html(body):
    return {"headers": [("Content-Type", "text/html; charset=utf-8")], "body": body}


# ── 판정기 ────────────────────────────────────────────────────

@pytest.mark.parametrize("body, verdict, ctx", [
    ("<p>vcdTOKEN'\"<></p>", "vuln", "html"),
    ('<input value="vcdTOKEN\'"<>">', "vuln", "attribute"),
    ("<script>var q = 'vcdTOKEN'\"<>';</script>", "vuln", "script"),
    ("<p>vcdTOKEN&#39;&quot;&lt;&gt;</p>", "potential", "html"),
    ("<p>vcdTOKEN</p>", "potential", "html"),
    ("<p>nothing</p>", "safe", ""),
])
def test_judge_reflection(body, verdict, ctx):
    v, c, _ = probe.judge_reflection(body, "vcdTOKEN", "vcdTOKEN'\"<>")
    assert (v, c) == (verdict, ctx)


def test_send_fills_siblings(monkeypatch):
    sent = []
    monkeypatch.setattr(core, "fetch", lambda url, **kw: sent.append((url, kw)) or Response(url, 200))
    p = Point("GET", "https://sesacedu.store/courses", "level", "query", fields={"category": "web", "level": "1"})
    probe.send(p, "X")
    assert dict(parse_qsl(urlsplit(sent[0][0]).query)) == {"category": "web", "level": "X"}
    f = Point("POST", "https://sesacedu.store/qna", "title", "form", fields={"title": "", "body": "b"})
    probe.send(f, "Y")
    assert sent[1][1] == {"method": "POST", "data": {"title": "Y", "body": "b"}}


# ── 수집 모듈 ──────────────────────────────────────────────────

def test_crawl_collects_links_forms_js(monkeypatch, fake_fetch):
    f = fake_fetch({"store/": html(HOME), "/assets/app.js": {"body": APP_JS}, "/courses?category=web&level=1": html("<p>강의</p>")})
    monkeypatch.setattr(surface_crawl, "fetch", f)
    pts = {(p.method, urlsplit(p.url).path, p.param, p.place) for p in surface_crawl.run(T, {"max_pages": "10", "skip": "logout"})}
    assert ("GET", "/courses", "category", "query") in pts and ("GET", "/courses", "level", "query") in pts
    assert ("GET", "/search", "keyword", "query") in pts
    assert {("POST", "/qna", n, "form") for n in ("title", "body", "csrf")} <= pts
    assert ("POST", "/qna", "board", "form") not in pts  # action 쿼리는 본문 파라미터가 아님
    assert ("GET", "/api/lectures", "keyword", "query") in pts
    assert ("GET", "/api/lectures/${id}/materials", "", "path") in pts
    assert ("GET", "/api/inline/ping", "x", "query") in pts
    assert not any("/notapi" in p[1] for p in pts)
    called = " ".join(f.calls)
    assert "evil.example" not in called and "logout" not in called and ".png" not in called


def test_import_parses_lines():
    pts = surface_import.run(T, {"urls": "https://sesacedu.store/a?x=1\n\nPOST /login email=a&pw=\n/b"})
    got = {(p.method, urlsplit(p.url).path, p.param, p.place) for p in pts}
    assert {("GET", "/a", "x", "query"), ("POST", "/login", "email", "form"), ("POST", "/login", "pw", "form"),
            ("GET", "/b", "", "path")} <= got


# ── 화면 흐름: 수집 → 고르기 → 점검 → 결과 ──────────────────────

def echo_fetch(escape_param=None):
    """쿼리 값을 본문에 그대로 넣어 주는 가짜 서버. escape_param 은 인코딩해서 돌려준다."""
    def fetch(url, **kw):
        q = dict(parse_qsl(urlsplit(url).query))
        q.update(kw.get("data") or {})
        parts = []
        for k, v in q.items():
            if k == escape_param:
                v = v.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
            parts.append(f"<p>{v}</p>")
        return Response(url, 200, [("Content-Type", "text/html")], "".join(parts))
    return fetch


@pytest.fixture
def seeded(app, client):
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹", "url": "https://sesacedu.store"})
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    urls = "https://sesacedu.store/courses?category=web&level=1\nPOST /qna title=&body=\nhttps://evil.example/x?a=1"
    page = client.post("/modules/surface_import/run", data={"target_id": tid, "urls": urls},
                       follow_redirects=True).get_data(as_text=True)
    assert "범위 밖 2개 제외" in page  # evil.example 의 엔드포인트·파라미터
    with app.app_context():
        ids = {r["param"]: r["id"] for r in get_db().execute("SELECT id, param FROM points WHERE param != ''")}
    return tid, ids


def test_collect_then_surface_page(client, seeded):
    tid, ids = seeded
    page = client.get(f"/surface?target={tid}").get_data(as_text=True)
    assert "/courses" in page and "category" in page and "입력값 반사 확인" in page
    assert set(ids) == {"category", "level", "title", "body"}


def test_probe_flow_and_dedupe(app, client, seeded, monkeypatch):
    tid, ids = seeded
    monkeypatch.setattr(core, "fetch", echo_fetch(escape_param="level"))
    data = {"target_id": tid, "module_id": "reflection_check", "confirm": "yes",
            "point": [ids["category"], ids["level"], ids["title"]]}
    page = client.post("/surface/probe", data=data, follow_redirects=True).get_data(as_text=True)
    assert "취약 1 · 잠재 1 · 안전 0, 건너뜀 1" in page  # POST(title)는 기본값 GET 이라 안 보냄

    with app.app_context():
        db = get_db()
        verdicts = {r["param"]: r["verdict"] for r in db.execute(
            "SELECT p.param, pc.verdict FROM point_checks pc JOIN points p ON p.id = pc.point_id")}
        assert verdicts == {"category": "vuln", "level": "potential"}
        rows = db.execute("SELECT id, location FROM findings").fetchall()
        assert len(rows) == 1 and rows[0]["location"].endswith("(query: category)")
        db.execute("UPDATE findings SET status = 'fixed'")
        db.commit()

    # 다시 돌려도 결과는 하나, 조치됨이었으면 재발로 미확인
    client.post("/surface/probe", data=data)
    with app.app_context():
        rows = get_db().execute("SELECT status FROM findings").fetchall()
        assert [r["status"] for r in rows] == ["open"]
    assert "입력값이 그대로 반사됨" in client.get(f"/?target={tid}").get_data(as_text=True)


def test_probe_requires_confirm_and_points(client, seeded, monkeypatch):
    tid, ids = seeded
    calls = []
    monkeypatch.setattr(core, "fetch", lambda url, **kw: calls.append(url))
    page = client.post("/surface/probe", data={"target_id": tid, "module_id": "reflection_check",
                                               "point": [ids["category"]]}, follow_redirects=True).get_data(as_text=True)
    assert "체크해야" in page
    page = client.post("/surface/probe", data={"target_id": tid, "module_id": "reflection_check", "confirm": "yes"},
                       follow_redirects=True).get_data(as_text=True)
    assert "지점을 고르세요" in page and calls == []


def test_probe_module_not_runnable_from_modules_tab(client, seeded):
    tid, _ = seeded
    page = client.post("/modules/reflection_check/run", data={"target_id": tid, "confirm": "yes"},
                       follow_redirects=True).get_data(as_text=True)
    assert "표면 탭에서" in page


def test_rerun_check_module_does_not_duplicate(app, client, monkeypatch, fake_fetch):
    from modules import http_security_headers
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹", "url": "https://sesacedu.store"})
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    for _ in range(2):
        client.post("/modules/http_security_headers/run", data={"target_id": 1, "path": "/"})
    with app.app_context():
        titles = [r["title"] for r in get_db().execute("SELECT title FROM findings")]
    assert len(titles) == len(set(titles))


# ── hidden 속성이 display 규칙에 밀리지 않아야 한다 ──────────────────
# .probe-params 는 display:flex 라 브라우저 기본 [hidden]{display:none} 이 밀린다.
# 그러면 고르지 않은 모듈의 입력칸까지 같이 보여서 어느 칸이 쓰이는지 알 수 없다.

def test_stylesheet_forces_hidden():
    from pathlib import Path
    css = (Path(__file__).resolve().parent.parent / "dashboard/static/style.css").read_text(encoding="utf-8")
    assert "[hidden] { display: none !important; }" in css


def test_only_selected_probe_params_are_shown(app, client):
    import re
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/surface_import/run",
                data={"target_id": tid, "urls": "https://sesacedu.store/courses?category=web"},
                follow_redirects=True)
    html = client.get(f"/surface?target={tid}").get_data(as_text=True)
    blocks = re.findall(r'<div class="probe-params" data-for="([^"]+)"([^>]*)>', html)
    assert len(blocks) >= 2                      # 지점 점검 모듈이 여럿이다
    shown = [mid for mid, attrs in blocks if "hidden" not in attrs]
    assert len(shown) == 1, f"보이는 입력칸 묶음은 하나여야 하는데 {shown}"


# ── 사전 고르는 칸은 모듈이 적어 둔 기본값을 골라 둬야 한다 ──────────
# 값은 '<폴더>|<파일>' 전체라 파일 이름만 적힌 기본값과 == 로는 영영 안 맞았다.
# 그래서 아무것도 선택되지 않고 브라우저가 첫 줄(backup-config.txt)을 골랐다.

def test_wordlist_select_honours_module_default(app, client):
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/surface_import/run",
                data={"target_id": tid, "urls": "https://sesacedu.store/courses?category=web"},
                follow_redirects=True)
    import re

    def selected(html, pattern):
        block = re.search(pattern, html, re.S)
        assert block, pattern
        sel = re.search(r'<option value="([^"]*)" selected', block.group(0))
        assert sel, "고른 사전이 없다 — 브라우저가 목록 첫 줄을 고르게 된다"
        return sel.group(1)

    # 대상 점검·수집 모듈은 모듈 탭에, 지점 점검 모듈은 표면 탭에 입력칸이 뜬다
    mods = client.get(f"/modules?target={tid}").get_data(as_text=True)
    assert selected(mods, r'action="[^"]*content_discovery/run".*?</form>').endswith("|web-common.txt")

    surf = client.get(f"/surface?target={tid}").get_data(as_text=True)
    assert selected(surf, r'data-for="payload_probe".*?</div>').endswith("|payload-reflect.txt")


def test_empty_url_list_is_an_error(app, client):
    """빈 칸으로 내면 '0개 수집' 이 아니라 왜 비었는지 말해야 한다."""
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.post("/modules/surface_import/run", data={"target_id": tid, "urls": "   "},
                       follow_redirects=True).get_data(as_text=True)
    assert "붙여 넣을 URL 이 없습니다" in page


# ── 파라미터가 하나도 없을 때 왜 못 고르는지 말해 줘야 한다 ───────────
# 주소만 모인 상태에서는 '전체 선택'을 눌러도 0개고, 점검을 누르면
# "점검할 지점을 고르세요" 만 떠서 무엇이 모자란지 알 수 없었다.

def test_surface_explains_when_no_parameters(app, client):
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/surface_import/run",
                data={"target_id": tid, "urls": "https://sesacedu.store/login"}, follow_redirects=True)
    html = client.get(f"/surface?target={tid}").get_data(as_text=True)
    assert "고를 수 있는 지점이 없습니다" in html
    assert 'id="pick-all"' in html and 'class="panel probe-bar" hidden' in html


def test_surface_shows_the_bar_once_a_parameter_exists(app, client):
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/surface_import/run",
                data={"target_id": tid, "urls": "https://sesacedu.store/backend/lectures?keyword=a"},
                follow_redirects=True)
    html = client.get(f"/surface?target={tid}").get_data(as_text=True)
    assert "고를 수 있는 지점이 없습니다" not in html
    assert 'name="point"' in html
