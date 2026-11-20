"""표면 자동 수집(11-20) — 부품(dashboard/discovery.py)과 연습 서버를 상대로 한 끝까지 실행."""
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

import demo_target
from dashboard import discovery as dv
from dashboard.core import Point, Response
from modules import surface_discover

ORIGIN = "http://127.0.0.1:5051"


# ── 부품 ──────────────────────────────────────────────────────

@pytest.mark.parametrize("raw, want", [
    ("/backend/lectures/123/material", "/backend/lectures/{id}/material"),
    ("/users/:userId", "/users/{userId}"),
    ("/courses/[id]", "/courses/{id}"),
    ("/a/550e8400-e29b-41d4-a716-446655440000", "/a/{id}"),
    ("/v2/items", "/v2/items"),
])
def test_normalize_path(raw, want):
    assert dv.normalize_path(raw) == want


def _reg_js(js):
    reg = dv.Registry()
    dv.extract_js(js, ORIGIN + "/", reg)
    return {(c.method, c.path): c for c in reg}


def test_js_finds_backend_paths_not_only_api():
    """예전 수집은 /api·/v1 로 시작하는 것만 잡아 새싹에듀 /backend 를 놓쳤다."""
    got = _reg_js(demo_target.APP_JS)
    assert ("GET", "/backend/courses") in got
    assert ("GET", "/backend/courses/{courseId}") in got
    assert ("GET", "/backend/admin/stats") in got
    assert ("GET", "/backend/courses/{courseId}/reviews") in got      # "/a/" + id + "/b"
    assert not any(p.endswith(".png") for _, p in got)                 # 정적 파일은 뺀다
    assert ("GET", "/reviews") not in got and ("GET", "/backend/courses/") not in got  # 결합 조각은 따로 안 잡는다


def test_js_reads_method_and_body_keys():
    got = _reg_js(demo_target.APP_JS)
    enroll = got[("POST", "/backend/enroll")]
    assert enroll.params == {"courseId": ("json", ""), "memberId": ("json", "")}
    assert {"keyword", "sort"} <= set(got[("GET", "/backend/courses")].params)
    assert got[("GET", "/backend/courses")].basis() == "추정"         # JS 만으로는 메서드 '추정'


def test_fetch_options_method_and_body():
    got = _reg_js("fetch('/backend/report/export', {method: 'POST', body: JSON.stringify({fmt, range: 1})})")
    c = got[("POST", "/backend/report/export")]
    assert set(c.params) == {"fmt", "range"} and c.params["fmt"][0] == "json"


def test_openapi_with_ref_and_places():
    reg = dv.Registry()
    assert dv.parse_openapi(demo_target.OPENAPI, ORIGIN + "/v3/api-docs", ORIGIN, reg) == 4
    got = {(c.method, c.path): c for c in reg}
    assert got[("POST", "/backend/enroll")].params == {"courseId": ("json", ""), "memberId": ("json", "")}
    assert got[("GET", "/backend/courses/{courseId}")].params["courseId"][0] == "path"
    assert got[("GET", "/backend/proxy")].basis() == "선언"


def test_actuator_mappings():
    doc = {"contexts": {"app": {"mappings": {"dispatcherServlets": {"dispatcherServlet": [
        {"details": {"requestMappingConditions": {"methods": ["POST"], "patterns": ["/backend/login"]}}},
        {"details": {"requestMappingConditions": {"methods": [], "patterns": ["/backend/lectures/{id}"]}}},
    ]}}}}}
    reg = dv.Registry()
    assert dv.parse_actuator_mappings(doc, ORIGIN, reg) == 2
    assert {(c.method, c.path) for c in reg} == {("POST", "/backend/login"), ("GET", "/backend/lectures/{id}")}


def test_robots_marks_disallow():
    reg = dv.Registry()
    maps = dv.parse_robots("Disallow: /internal-report\nAllow: /\nSitemap: /sitemap.xml", ORIGIN, reg)
    assert maps == [ORIGIN + "/sitemap.xml"]
    c = next(iter(reg))
    assert c.path == "/internal-report" and "Disallow" in c.evidence[0]


def _resp(status, body="", ctype="text/html"):
    return Response("u", status, headers=[("Content-Type", ctype)], body=body)


def test_verifier_catches_soft_404():
    """없는 주소에도 같은 화면 200 을 주면 '있음' 이 아니라 가짜 200 이다."""
    shell = "<div id=root></div>"
    v = dv.Verifier(lambda url: _resp(200, shell))
    c = dv.Candidate("GET", ORIGIN + "/app/dashboard")
    v.check(c)
    assert (c.state, c.status) == ("soft_404", 200)


@pytest.mark.parametrize("status, state", [(200, "exists"), (401, "auth_required"), (403, "auth_required"),
                                           (405, "method_mismatch"), (500, "server_error"), (404, "not_found")])
def test_verifier_states(status, state):
    def get(url):
        return _resp(404, "nope") if "/zq" in url else _resp(status, f"real {status}")
    c = dv.Candidate("GET", ORIGIN + "/backend/x")
    dv.Verifier(get).check(c)
    assert c.state == state and c.status == status


def test_verifier_uses_options_for_post_and_never_sends_post():
    sent = []

    def get(url):
        sent.append(("GET", url))
        return _resp(404, "nope")

    def options(url):
        sent.append(("OPTIONS", url))
        return Response(url, 200, headers=[("Allow", "POST, OPTIONS")])
    c = dv.Candidate("POST", ORIGIN + "/backend/enroll")
    dv.Verifier(get, options).check(c)
    assert c.state == "exists" and all(m in ("GET", "OPTIONS") for m, _ in sent)


def test_score_reasons():
    c = dv.Candidate("GET", ORIGIN + "/backend/proxy", params={"url": ("query", "")}, state="exists")
    dv.score(c)
    assert c.risk >= 20 and any("SSRF" in r for r in c.reasons)
    page = dv.Candidate("GET", ORIGIN + "/about", kind="page")
    assert dv.score(page).risk == 0


# ── 연습 서버를 상대로 끝까지 ─────────────────────────────────────

@pytest.fixture
def demo_fetch(monkeypatch):
    """surface_discover 의 요청을 연습 서버(Flask 테스트 클라이언트)로 돌린다."""
    client = demo_target.app.test_client()
    sent = []

    def fake(url, method="GET", **kw):
        s = urlsplit(url)
        assert s.netloc == "127.0.0.1:5051", url
        sent.append((method, url))
        r = client.open(s.path + ("?" + s.query if s.query else ""), method=method)
        return Response(url, r.status_code, headers=list(r.headers.items()), body=r.get_data(as_text=True))
    monkeypatch.setattr(surface_discover, "fetch", fake)
    return sent


def _run(steps="page,meta,spec,js,verify"):
    params = {p["name"]: p.get("default", "") for p in surface_discover.META["params"]}
    params["steps"] = steps
    return surface_discover.run(SimpleNamespace(url=ORIGIN), params)


def test_end_to_end_against_demo(demo_fetch):
    pts = _run()
    ends = {(p.method, urlsplit(p.url).path): p for p in pts if not p.param}
    params = {(p.method, urlsplit(p.url).path, p.param, p.place) for p in pts if p.param}
    # 페이지·폼
    assert ("POST", "/guestbook", "message", "form") in params
    # JS 번들·소스맵·API 명세
    assert ("POST", "/backend/enroll", "courseId", "json") in params
    assert ("POST", "/backend/report/export", "fmt", "json") in params
    assert ("GET", "/backend/courses/{courseId}", "courseId", "path") in params
    assert ("GET", "/backend/proxy", "url", "query") in params
    # robots
    assert ("GET", "/internal-report") in ends
    # 확인 결과
    assert ends[("GET", "/backend/courses")].state == "exists"
    assert ends[("GET", "/backend/admin/stats")].state == "auth_required"
    assert ends[("GET", "/backend/admin/stats")].status == 403
    assert ends[("POST", "/backend/enroll")].state == "exists"          # OPTIONS 로 확인
    assert ends[("GET", "/app/dashboard")].state == "soft_404"
    assert ends[("GET", "/internal-report")].state == "not_found"
    # 근거와 점수
    ev = json.loads(ends[("GET", "/backend/proxy")].evidence)
    assert "spec" in ev["sources"] and ev["basis"] == "선언"
    assert ends[("GET", "/backend/proxy")].risk > ends[("GET", "/backend/courses")].risk
    # 상태를 바꾸는 요청은 보내지 않았다
    assert {m for m, _ in demo_fetch} <= {"GET", "OPTIONS"}
    assert all(isinstance(p, Point) for p in pts)


def test_steps_can_be_limited(demo_fetch):
    _run("meta")
    assert {urlsplit(u).path for _, u in demo_fetch} <= {"/robots.txt", "/sitemap.xml"}


def test_skip_words_are_not_requested(demo_fetch):
    params = {p["name"]: p.get("default", "") for p in surface_discover.META["params"]}
    params["skip"] = "admin"
    surface_discover.run(SimpleNamespace(url=ORIGIN), params)
    assert not any("admin" in u for _, u in demo_fetch)


def test_saved_points_keep_state_and_risk(app, client, monkeypatch, demo_fetch):
    """앱으로 돌리면 대상 탭 표면에 상태·코드·점수가 같이 저장된다."""
    from dashboard.db import get_db
    client.post("/targets", data={"project": "sesacedu", "role": "practice", "name": "연습",
                                  "url": ORIGIN})
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/surface_discover/run", data={"target_id": tid, "confirm": "yes",
                                                        **{p["name"]: p.get("default", "") for p in surface_discover.META["params"]}},
                follow_redirects=True)
    with app.app_context():
        row = get_db().execute("SELECT state, status, risk FROM points WHERE url LIKE '%/backend/admin/stats' "
                               "AND param = ''").fetchone()
    assert row is not None and (row["state"], row["status"]) == ("auth_required", 403) and row["risk"] > 0
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert "JSON 본문" in page


# ── 2단계: 대상 탭에 상태·점수·근거·추천 점검 ──────────────────────

@pytest.mark.parametrize("name, place, want", [
    ("url", "query", ["SSRF"]), ("file", "query", ["FILE"]), ("courseId", "path", ["IDOR"]),
    ("keyword", "query", ["INJECT"]), ("memo", "json", ["INJECT"]), ("courseId", "json", ["IDOR"]),
])
def test_suggest(name, place, want):
    assert dv.suggest(name, place) == want


@pytest.fixture
def discovered(app, client, demo_fetch):
    from dashboard.db import get_db
    client.post("/targets", data={"project": "sesacedu", "role": "practice", "name": "연습", "url": ORIGIN})
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/surface_discover/run", data={"target_id": tid, "confirm": "yes",
                **{p["name"]: p.get("default", "") for p in surface_discover.META["params"]}})
    return tid


def test_surface_shows_state_risk_and_evidence(client, discovered):
    page = client.get(f"/targets?target={discovered}").get_data(as_text=True)
    assert 'class="st st-auth_required"' in page and "<b>403</b>" in page
    assert 'class="risk r-' in page and "근거 · 이유" in page
    assert "메서드 <b>선언</b>" in page and "API 명세" in page
    # 위험 높은 순이 기본 — 가장 위 묶음이 0점짜리 '/' 가 아니다
    first = page.index('<tr class="ep">')
    assert "위험 " in page[first:first + 2500]


def test_missing_paths_are_hidden_until_asked(client, discovered):
    page = client.get(f"/targets?target={discovered}").get_data(as_text=True)
    assert "/app/dashboard" not in page and "숨김" in page
    shown = client.get(f"/targets?target={discovered}&show=all").get_data(as_text=True)
    assert "/app/dashboard" in shown and "st-soft_404" in shown


def test_state_filter(client, discovered):
    page = client.get(f"/targets?target={discovered}&state=auth_required").get_data(as_text=True)
    assert "/backend/admin/stats" in page and "/backend/courses<" not in page.replace("</span>", "<")


def test_suggestions_point_to_modules(client, discovered):
    page = client.get(f"/targets?target={discovered}&sort=path").get_data(as_text=True)
    assert 'class="sg" data-mod=' in page                               # 주입 → 지점 점검 모듈
    assert "SSRF·열린 리다이렉트</span>" in page                         # 모듈 없는 추천은 표시만
