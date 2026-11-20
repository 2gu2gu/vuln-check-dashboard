"""취약점별 지점 점검(11-20): ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

가짜 서버를 세워 '받는 구간이 아니면 거기서 끝', '후보면 단계를 올려 가다 확인되면 멈춤' 을 본다.
"""
from html import escape
from urllib.parse import parse_qs, urlsplit

from dashboard import core
from dashboard.core import Point, Response
from modules import sqli_probe, stored_xss_probe, traversal_probe, xss_probe

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


def test_xss_value_echoed_still_encoded_is_safe_not_potential(monkeypatch):
    """경로 변수를 풀지 않고 응답에 담는 화면(Next.js 라우터 묶음) — 스크립트 블록 안이어도 깨뜨릴 수 없다.

    11-20 관리자 웹 `/users/{userId}` 등 4곳을 브라우저로 확인한 결과를 모듈에 넣은 것이다.
    """
    p = Point(method="GET", url="https://sesacedu.store/users/{userId}", param="userId", place="path",
              sample="1", fields={})
    _server(monkeypatch, lambda url: (200, '<script>self.__next_f.push([1,"{\\"params\\":{\\"userId\\":\\"'
                                           + url.rsplit("/", 1)[-1] + '\\"}}"])</script>'))
    c = xss_probe.run(T, [p], {})[0]
    assert c.verdict == "safe"
    assert "퍼센트 인코딩된 채로만 돌아옴" in c.evidence
    assert "스크립트 블록" in c.evidence  # 받는 구간은 스크립트 블록이라고 적되, 실행되지 않는다고 결론낸다
    assert "필터가 있음" not in c.evidence


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


# ── 표면 수집 하나로(11-20) ──────────────────────────────────────

def test_old_collectors_are_hidden_but_still_runnable(app, client):
    tid = _seed_points(app, client)                     # surface_import 로 넣는다 — 숨겨도 돈다
    page = client.get(f"/modules?target={tid}").get_data(as_text=True)
    assert 'data-mod="surface_collect"' in page
    for old in ("surface_crawl", "surface_discover", "surface_import", "har_import", "content_discovery"):
        assert f'data-mod="{old}"' not in page, old
    with app.app_context():
        from dashboard.db import get_db
        assert get_db().execute("SELECT COUNT(*) FROM points WHERE param = 'keyword'").fetchone()[0] == 1


def test_surface_collect_reads_pasted_formats(monkeypatch):
    from modules import surface_collect
    assert surface_collect.paste_kind('{"log": {"entries": []}}') == "har"
    assert surface_collect.paste_kind("/admin                (Status: 200) [Size: 10]") == "tool"
    assert surface_collect.paste_kind("https://sesacedu.store/a?x=1") == "urls"
    pts = surface_collect.run(T, {"mode": "paste", "paste": "https://sesacedu.store/a?x=1\n/b?y=2"})
    assert {(p.param) for p in pts} >= {"x", "y"}


def test_surface_collect_runs_steps_in_order(monkeypatch):
    from modules import content_discovery, surface_collect, surface_discover
    order = []
    monkeypatch.setattr(surface_discover, "run", lambda t, p: order.append("auto") or [])
    monkeypatch.setattr(content_discovery, "run", lambda t, p: order.append("hidden") or [])
    surface_collect.run(T, {"mode": "deep", "paste": "https://sesacedu.store/a?x=1"})
    assert order == ["auto", "hidden"]
    order.clear()
    surface_collect.run(T, {"mode": "auto"})
    assert order == ["auto"]


def test_endpoint_count_leaves_out_missing_paths(app, client):
    """없는 경로(404·가짜 200)는 엔드포인트 수에서 뺀다 — '30개인데 파라미터 9개' 처럼 부풀었다(11-20)."""
    from tests.test_app import add_target, target_id
    from dashboard.db import get_db
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    tid = target_id(app, "https://sesacedu.store")
    with app.app_context():
        db = get_db()
        for url, st in (("https://sesacedu.store/ok", "exists"), ("https://sesacedu.store/gone", "not_found")):
            db.execute("INSERT INTO points (target_id, method, url, param, place, source, first_seen, last_seen, state) "
                       "VALUES (?, 'GET', ?, '', 'path', 'js', 'x', 'x', ?)", [tid, url, st])
        db.commit()
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert "<small>엔드포인트</small><strong>1</strong>" in page and "없는 경로 1개는 빼고 셈" in page
    assert "페이지 1 ·" in page


# ── 주소 단위 점검(11-20): 정보 노출 · 보안 헤더 ──────────────────

def _ep(url="https://sesacedu.store/api"):
    return Point(method="GET", url=url, param="", place="path")


def _hserver(monkeypatch, handler):
    def fetch(url, method="GET", headers=None, **_kw):
        status, hdrs, body = handler(url, method, headers or {})
        return Response(url=url, status=status, headers=hdrs, body=body)
    monkeypatch.setattr(core, "fetch", fetch)


def test_info_leak_finds_stack_trace_in_deep_stage(monkeypatch):
    from modules import info_leak_probe
    def h(url, method, headers):
        if "%7B" in url:
            return 500, [], "java.lang.IllegalArgumentException at org.apache.catalina.Foo(Foo.java:1)"
        return 200, [("Server", "nginx")], "<html>ok</html>"
    _hserver(monkeypatch, h)
    c = info_leak_probe.run(T, [_ep()], {})[0]
    assert c.verdict == "vuln" and "스택 트레이스" in c.title and "③ 심화" in c.evidence


def test_info_leak_version_header_is_potential(monkeypatch):
    from modules import info_leak_probe
    _hserver(monkeypatch, lambda url, method, h: (200, [("Server", "nginx/1.24.0")], "ok"))
    c = info_leak_probe.run(T, [_ep()], {})[0]
    assert c.verdict == "potential" and "Server" in c.title


def test_info_leak_finds_a_secret_shaped_value_in_the_body(monkeypatch):
    """팀원 도구(piroim/site-scanner)의 생각을 가져온 것 — 응답 본문에 비밀값이 그대로 박혀 나오는가."""
    from modules import info_leak_probe
    body = '<script>window.cfg={apiKey:"AbCdEf0123456789AbCdEf01"};</script>'
    _hserver(monkeypatch, lambda url, method, h: (200, [], body))
    c = info_leak_probe.run(T, [_ep()], {})[0]
    assert c.verdict == "vuln" and "API 키" in c.title and "② 기본" in c.evidence


def test_info_leak_does_not_cry_wolf_on_a_bare_secret_name(monkeypatch):
    """이름만 맞은 것으로는 적지 않는다 — 값의 모양까지 맞아야 한다."""
    from modules import info_leak_probe
    _hserver(monkeypatch, lambda url, method, h: (200, [], '<label>password</label><input name="apiKey">'))
    c = info_leak_probe.run(T, [_ep()], {})[0]
    assert "노출" not in (c.title or "") or "API 키" not in c.title


def test_info_leak_flags_a_missing_path_that_answers_with_the_whole_screen(monkeypatch):
    """노션 '정보노출' 의 'Next.js 관리자 404가 전체 RSC 페이로드로 응답' 과 같은 모양."""
    from modules import info_leak_probe
    big = '<script>self.__next_f.push([1,"' + "x" * 3000 + '"])</script>'
    _hserver(monkeypatch, lambda url, method, h: (200, [], big) if "/zz" in url else (200, [], "ok"))
    c = info_leak_probe.run(T, [_ep()], {})[0]
    assert c.verdict == "potential" and "없는 경로가 화면 데이터를 통째로 응답" in c.title


def test_header_probe_flags_cors_reflecting_any_origin(monkeypatch):
    from modules import header_probe
    full = [("Strict-Transport-Security", "max-age=1"), ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"), ("Content-Type", "application/json")]
    def h(url, method, headers):
        extra = [("Access-Control-Allow-Origin", headers["Origin"]), ("Access-Control-Allow-Credentials", "true")] \
            if headers.get("Origin") else []
        return 200, full + extra, "{}"
    _hserver(monkeypatch, h)
    c = header_probe.run(T, [_ep()], {})[0]
    assert c.verdict == "vuln" and "CORS" in c.title and "④ 우회" in c.evidence


def test_header_probe_all_good_is_safe(monkeypatch):
    from modules import header_probe
    full = [("Strict-Transport-Security", "max-age=1"), ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"), ("Content-Type", "application/json")]
    _hserver(monkeypatch, lambda url, method, h: (200, full, "{}"))
    assert header_probe.run(T, [_ep()], {})[0].verdict == "safe"


def test_endpoint_module_runs_once_per_address_and_stores_on_it(app, client, monkeypatch):
    tid = _seed_points(app, client)                     # /backend/lectures?keyword&size — 파라미터 둘, 주소 하나
    _hserver(monkeypatch, lambda url, method, h: (200, [("Server", "nginx/1.24.0")], "ok"))
    with app.app_context():
        from dashboard.db import get_db
        ids = [r["id"] for r in get_db().execute("SELECT id FROM points WHERE param != ''")]
    r = client.post("/surface/probe", headers=FETCH, data={"target_id": tid, "module_id": "info_leak_probe",
                                                           "point": ids, "confirm": "yes"})
    assert r.json["ok"]
    with app.app_context():
        from dashboard.db import get_db
        rows = get_db().execute("SELECT p.param, pc.verdict FROM point_checks pc JOIN points p ON p.id = pc.point_id "
                                "WHERE pc.module_id = 'info_leak_probe'").fetchall()
    assert [(r["param"], r["verdict"]) for r in rows] == [("", "potential")]    # 주소 하나에 한 번
    html = client.get(f"/modules/info_leak_probe/panel?target={tid}&partial=1").get_data(as_text=True)
    assert "고를 주소" in html and "/backend/lectures" in html


# ── 심화 모듈은 고른 지점에(11-20) ──────────────────────────────────

PICK = {"point_url": "https://sesacedu.store/backend/search", "point_param": "id", "point_place": "query",
        "point_sample": "7"}


def test_deep_sqli_hits_the_picked_point_by_response_shape(monkeypatch):
    from projects.sesacedu.modules import lecture_sqli
    sent = []

    def fetch(url, **_kw):
        sent.append(url)
        v = _q(url, "id")
        return Response(url=url, status=200, body="row " * (30 if "1=1" in v else 2))
    monkeypatch.setattr(lecture_sqli, "fetch", fetch)
    r = lecture_sqli.run(T, {"mode": "probe", "dbms": "sqlite", "limit": "5", "offset": "0",
                             "context": "number", **PICK})
    assert r.summary.startswith("주입됩니다") and "/backend/search (query: id)" in r.summary
    assert all(u.startswith("https://sesacedu.store/backend/search?id=7%20AND%20") for u in sent)
    assert r.findings[0].location == "https://sesacedu.store/backend/search (query: id)"


def test_deep_traversal_hits_the_picked_point(monkeypatch):
    from projects.sesacedu.modules import material_traversal
    sent = []
    monkeypatch.setattr(material_traversal, "fetch",
                        lambda url, **kw: sent.append(url) or Response(url=url, status=200, body="root:x:0:0"))
    material_traversal.run(T, {"paths": "etc/passwd", "scheme": "none", "depth": "2", "lecture": "123",
                               "point_url": "https://sesacedu.store/files", "point_param": "name"})
    assert sent[0].startswith("https://sesacedu.store/files?name=") and "lectures" not in sent[0]


def test_deep_module_popup_picks_one_point_and_run_fills_it(app, client, monkeypatch):
    from projects.sesacedu.modules import lecture_sqli
    tid = _seed_points(app, client)
    html = client.get(f"/modules/sesacedu_lecture_sqli/panel?target={tid}&partial=1").get_data(as_text=True)
    assert 'type="radio" name="point"' in html and 'class="mp-all"' not in html
    monkeypatch.setattr(lecture_sqli, "fetch", lambda url, **kw: Response(url=url, status=200, body="x"))
    with app.app_context():
        from dashboard.db import get_db
        pid = get_db().execute("SELECT id FROM points WHERE param = 'keyword'").fetchone()["id"]
    client.post("/modules/sesacedu_lecture_sqli/run", headers=FETCH,
                data={"target_id": tid, "point": pid, "confirm": "yes", "mode": "probe", "dbms": "sqlite"})
    with app.app_context():
        from dashboard.db import get_db
        import json
        params = json.loads(get_db().execute("SELECT params FROM runs WHERE module_id = 'sesacedu_lecture_sqli'")
                            .fetchone()["params"])
    assert params["point_url"] == "https://sesacedu.store/backend/lectures" and params["point_param"] == "keyword"


# ── 저장형 XSS 지점 점검(11-20) ─────────────────────────────────

def _write_point(param="content"):
    return Point(method="POST", url="https://sesacedu.store/backend/posts", param=param, place="form",
                 sample="hi", fields={param: "hi"})


def test_stored_xss_runs_without_a_write_confirm_box():
    """확인 칸은 뺐다(11-20 사용자 지시) — 글이 남는다는 경고는 설명에 그대로 있다."""
    assert "남습니다" in stored_xss_probe.META["description"]
    assert "직접 지우세요" in stored_xss_probe.META["description"]
    assert not any(p["name"] == "write_ack" for p in stored_xss_probe.META["params"])


def test_stored_xss_stops_when_nothing_is_stored(monkeypatch):
    sent = _server(monkeypatch, lambda url: (200, "아무것도 남지 않음"))
    c = stored_xss_probe.run(T, [_write_point()], {})[0]
    assert c.verdict == "safe" and "후보 제외" in c.evidence
    assert len(sent) == 2                                   # 쓰기 한 번 + 다시 읽기 한 번


def test_stored_xss_found_when_payload_survives_the_read(monkeypatch):
    kept = []

    def handler(url):
        if url.endswith("/backend/posts") and kept:          # 다시 읽기 — 마지막으로 쓴 값이 보인다
            return 200, "<div>" + kept[-1] + "</div>"
        return 200, "등록됨"
    sent = []

    def fetch(url, method="GET", data=None, **_kw):
        sent.append((method, url))
        if method == "POST":
            kept.append((data or {}).get("content", ""))
            return Response(url=url, status=200, body="등록됨")
        status, body = handler(url)
        return Response(url=url, status=status, body=body)
    monkeypatch.setattr(core, "fetch", fetch)
    c = stored_xss_probe.run(T, [_write_point()], {})[0]
    assert c.verdict == "vuln" and "저장형 XSS 후보" in c.title
    assert "② 기본" in c.evidence and "③ 심화" not in c.evidence


def test_stored_xss_reads_the_given_urls(monkeypatch):
    seen = []

    def fetch(url, method="GET", **_kw):
        seen.append(url)
        return Response(url=url, status=200, body="")
    monkeypatch.setattr(core, "fetch", fetch)
    stored_xss_probe.run(T, [_write_point()], {"write_ack": "WRITE",
                                                  "read_urls": "https://sesacedu.store/board\n"})
    assert "https://sesacedu.store/board" in seen


# ── 인증 방식 여러 가지(11-20 사용자 요청) ───────────────────────────

def test_auth_ways_make_the_header_line(app, client):
    from tests.test_app import add_target, target_id
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    tid = target_id(app, "https://sesacedu.store")
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    for label in ("Bearer 토큰", "쿠키 주입", "Basic 인증", "API 키"):
        assert label in page
    client.post(f"/targets/{tid}/auth", data={"way": "bearer", "token": "Bearer abc"}, follow_redirects=True)
    client.post(f"/targets/{tid}/auth", data={"way": "cookie", "cookie": "JSESSIONID=1"}, follow_redirects=True)
    with app.app_context():
        from dashboard.db import get_db
        text = get_db().execute("SELECT headers FROM targets WHERE id = ?", [tid]).fetchone()["headers"]
    assert text.splitlines() == ["Authorization: Bearer abc", "Cookie: JSESSIONID=1"]   # 둘 다 남는다
    client.post(f"/targets/{tid}/auth", data={"way": "basic", "ident": "a@b.c", "secret": "pw"},
                follow_redirects=True)
    with app.app_context():
        from dashboard.db import get_db
        text = get_db().execute("SELECT headers FROM targets WHERE id = ?", [tid]).fetchone()["headers"]
    assert "Authorization: Basic YUBiLmM6cHc=" in text and "Cookie: JSESSIONID=1" in text   # 같은 이름만 바뀐다
    r = client.post(f"/targets/{tid}/auth", data={"way": "apikey", "name": "X API", "value": "k"},
                    follow_redirects=True)
    assert "헤더 이름은" in r.get_data(as_text=True)


def test_old_point_modules_are_tidied(app, client):
    tid = _seed_points(app, client)
    page = client.get(f"/modules?target={tid}").get_data(as_text=True)
    assert 'data-mod="reflection_check"' not in page            # XSS 점검 ① 이 같은 일을 한다
    assert "사전으로 입력값 넣어 보기 (심화)" in page and "새싹에듀 XSS 조합 넣어 보기 (심화)" in page


# ── 파라미터가 없는 대상도 주소 단위로 점검(11-20, 관리자 웹 지적) ──────────

def test_targets_page_lets_you_pick_addresses_for_endpoint_modules(app, client, monkeypatch):
    """관리자 웹처럼 파라미터가 하나도 안 모인 대상에서도 보안 헤더·정보 노출은 돌아야 한다."""
    from tests.test_app import add_target, target_id
    add_target(client, "https://sesacedu.store", name="관리자 웹")
    tid = target_id(app, "https://sesacedu.store")
    client.post("/modules/surface_import/run", data={"target_id": tid,
                "urls": "https://sesacedu.store/dashboard\nhttps://sesacedu.store/users"},
                follow_redirects=True)
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    bar = page.split('class="panel probe-bar"', 1)[-1].split("</div>", 1)[0]
    assert "hidden" not in bar.split(">", 1)[0]                 # 파라미터가 없어도 점검 막대는 뜬다
    assert 'data-unit="endpoint"' in page                       # 주소 줄에 고르는 칸이 있다
    with app.app_context():
        from dashboard.db import get_db
        ids = [r["id"] for r in get_db().execute("SELECT id FROM points WHERE target_id = ?", [tid])]
    _hserver(monkeypatch, lambda url, method, h: (200, [("Content-Type", "text/html")], "<html>"))
    r = client.post("/surface/probe", headers=FETCH, data={"target_id": tid, "module_id": "header_probe",
                                                           "point": ids, "confirm": "yes"})
    assert r.json["ok"]
    with app.app_context():
        from dashboard.db import get_db
        got = get_db().execute("SELECT COUNT(*) FROM point_checks WHERE module_id = 'header_probe'").fetchone()[0]
    assert got == 2                                             # 주소 두 개에 판정이 하나씩


def test_popup_says_why_there_is_nothing_to_pick(app, client):
    """모은 주소는 있는데 파라미터가 없을 때(React·Next.js 화면) 빈 표 대신 이유를 적는다."""
    from tests.test_app import add_target, target_id
    add_target(client, "https://sesacedu.store", name="관리자 웹")
    tid = target_id(app, "https://sesacedu.store")
    client.post("/modules/surface_import/run", data={"target_id": tid, "urls": "https://sesacedu.store/dashboard"},
                follow_redirects=True)
    html = client.get(f"/modules/xss_probe/panel?target={tid}&partial=1").get_data(as_text=True)
    assert "이 모듈이 고를 지점이 없습니다" in html and "HAR" in html
    assert "고를 지점 0개" in html
    head = client.get(f"/modules/header_probe/panel?target={tid}&partial=1").get_data(as_text=True)
    assert "고를 주소 1개" in head and "/dashboard" in head       # 주소 단위 모듈은 그대로 고를 수 있다


def test_targets_page_shows_the_address_verdict_on_its_row(app, client, monkeypatch):
    """주소 단위 점검 결과는 파라미터 줄이 아니라 그 주소 줄에 붙어 보인다(11-20)."""
    from tests.test_app import add_target, target_id
    add_target(client, "https://sesacedu.store", name="관리자 웹")
    tid = target_id(app, "https://sesacedu.store")
    client.post("/modules/surface_import/run", data={"target_id": tid, "urls": "https://sesacedu.store/dashboard"},
                follow_redirects=True)
    with app.app_context():
        from dashboard.db import get_db
        ids = [r["id"] for r in get_db().execute("SELECT id FROM points WHERE target_id = ?", [tid])]
    _hserver(monkeypatch, lambda url, method, h: (200, [("Content-Type", "text/html")], "<html>"))
    client.post("/surface/probe", headers=FETCH, data={"target_id": tid, "module_id": "header_probe",
                                                       "point": ids, "confirm": "yes"})
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    row = page.split("/dashboard", 1)[-1].split("</tr>", 1)[0]
    assert "보안 헤더 점검" in row and "vchip" in row


def test_hidden_paths_params_can_still_be_picked(app, client):
    """없는 경로로 판정된 주소 안의 파라미터(경로 틀 /users/{userId})도 고를 수 있어야 한다(11-20 지적)."""
    from tests.test_app import add_target, target_id
    add_target(client, "https://sesacedu.store", name="관리자 웹")
    tid = target_id(app, "https://sesacedu.store")
    client.post("/modules/surface_import/run", data={"target_id": tid,
                "urls": "https://sesacedu.store/users?userId=1\nhttps://sesacedu.store/dashboard"},
                follow_redirects=True)
    with app.app_context():
        from dashboard.db import get_db
        db = get_db()
        pid = db.execute("SELECT id FROM points WHERE param = 'userId'").fetchone()["id"]
        # 표면 수집이 '없는 경로' 로 판정한 모습 — 주소 줄(파라미터 없는 행)에 상태가 붙는다
        db.execute("UPDATE points SET state = 'not_found', status = 404 WHERE param = '' AND url LIKE '%/users'", [])
        db.execute("UPDATE points SET state = 'exists', status = 200 WHERE param = '' AND url LIKE '%/dashboard'", [])
        db.commit()
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    # 고를 파라미터가 전부 '없는 경로' 안에 있으면 처음부터 펴서 보여 준다(11-20 사용자 지적)
    assert "펴서 보여 주고 있습니다" in page
    assert f'name="point" value="{pid}"' in page or f'value="{pid}"' in page
    panel = client.get(f"/modules/xss_probe/panel?target={tid}&partial=1").get_data(as_text=True)
    assert f'value="{pid}"' in panel                                        # 팝업에서는 그냥 고를 수 있다


def test_surface_opens_hidden_rows_when_every_pickable_param_is_hidden(app, client):
    """관리자 웹처럼 고를 파라미터가 전부 '없는 경로' 안에 있으면 처음부터 펴서 보여 준다.

    11-20 사용자 지적: 안내만 띄우고 '보이기' 를 한 번 더 누르게 하면 전체 선택이 0개가 된다.
    """
    tid = _seed_points(app, client)
    with app.app_context():
        from dashboard.db import get_db
        db = get_db()
        urls = [r[0] for r in db.execute(
            "SELECT DISTINCT url FROM points WHERE target_id = ? AND param != ''", [tid])]
        for u in urls:                     # 파라미터가 있는 주소를 통째로 '없는 경로' 로 만든다
            db.execute("UPDATE points SET state = 'not_found' WHERE target_id = ? AND url = ?", [tid, u])
        db.commit()
    html = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert "펴서 보여 주고 있습니다" in html
    assert 'name="point"' in html          # 숨긴 채였다면 고를 칸이 하나도 없다
