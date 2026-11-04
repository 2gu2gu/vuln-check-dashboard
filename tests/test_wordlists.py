"""사전 읽기, 숨은 경로 찾기, 사전으로 입력값 넣어 보기, 칼리 결과 가져오기."""
import json
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from dashboard import wordlists
from dashboard.core import Point, Response, Target
from dashboard.db import get_db
from modules import content_discovery, import_tool_output, payload_probe

T = Target(1, "t", "https://sesacedu.store")


def pick(name):
    """저장소에 들어 있는 사전 하나를 고른 값으로."""
    for o in wordlists.available():
        if o["label"].endswith(name):
            return o["value"]
    raise AssertionError(f"사전을 찾지 못했습니다: {name}")


# ── 사전 읽기 ─────────────────────────────────────────────────

def test_bundled_lists_are_found():
    labels = [o["label"] for o in wordlists.available()]
    assert any(l.endswith("web-common.txt") for l in labels)
    assert all(l.startswith("기본 / ") for l in labels)


def test_load_skips_comments_and_blanks():
    lines, cut = wordlists.load(pick("web-common.txt"))
    assert not cut and lines and all(line.strip() and not line.startswith("#") for line in lines)
    assert "admin" in lines


def test_load_honours_limit():
    lines, cut = wordlists.load(pick("web-common.txt"), limit=3)
    assert len(lines) == 3 and cut


def test_extra_root_from_env(tmp_path, monkeypatch):
    (tmp_path / "my.txt").write_text("# 메모\n\nalpha\nbeta\n", encoding="utf-8")
    monkeypatch.setenv("DASH_WORDLISTS", str(tmp_path))
    assert any(o["label"].endswith("my.txt") for o in wordlists.available())
    assert wordlists.load(pick("my.txt"))[0] == ["alpha", "beta"]


@pytest.mark.parametrize("choice", ["", "nope.txt", "/etc|passwd", "C:\\Windows|win.ini"])
def test_load_refuses_paths_outside_known_roots(choice):
    with pytest.raises(ValueError):
        wordlists.load(choice)


def test_load_refuses_escaping_a_known_root():
    root = pick("web-common.txt").split("|")[0]
    with pytest.raises(ValueError):
        wordlists.load(f"{root}|../run.py")


# ── 숨은 경로 찾기 ────────────────────────────────────────────

def fake_site(pages, missing_body="<h1>Not Found</h1>", missing_status=404):
    """pages 에 있는 경로만 200, 나머지는 '없음' 응답."""
    calls = []

    def fetch(url, **_kw):
        path = urlsplit(url).path.strip("/")
        calls.append(path)
        if path in pages:
            return Response(url, 200, [], pages[path])
        return Response(url, missing_status, [], missing_body)
    fetch.calls = calls
    return fetch


def test_discovery_finds_unlinked_paths(monkeypatch):
    monkeypatch.setattr(content_discovery, "fetch", fake_site({"admin": "<h1>관리</h1>", "backup": "x" * 400}))
    points = content_discovery.run(T, {"wordlist": pick("web-common.txt"), "base": "/", "limit": "20"})
    found = {urlsplit(p.url).path for p in points}
    assert "/admin" in found and "/backup" in found
    assert all(p.source == "wordlist" and p.method == "GET" for p in points)


def test_discovery_ignores_soft_404(monkeypatch):
    """없는 경로에도 200 과 같은 페이지를 주는 서버에 속지 않는다."""
    same = "<html>앱 화면</html>"
    monkeypatch.setattr(content_discovery, "fetch",
                        fake_site({}, missing_body=same, missing_status=200))
    assert content_discovery.run(T, {"wordlist": pick("web-common.txt"), "base": "/", "limit": "20"}) == []


def test_discovery_respects_base_and_limit(monkeypatch):
    f = fake_site({})
    monkeypatch.setattr(content_discovery, "fetch", f)
    content_discovery.run(T, {"wordlist": pick("web-common.txt"), "base": "/backend", "limit": "5"})
    probes = [c for c in f.calls if "vcd" not in c]
    assert len(probes) == 5 and all(c.startswith("backend/") for c in probes)


# ── 사전으로 입력값 넣어 보기 ───────────────────────────────────

def echo(transform=lambda v: v, extra=""):
    def fetch(url, **kw):
        q = dict(parse_qs(urlsplit(url).query))
        value = (kw.get("data") or {}).get("q") or (q.get("q", [""])[0])
        return Response(url, 200, [("Content-Type", "text/html")], f"<p>{transform(value)}</p>{extra}")
    return fetch


POINT = Point("GET", "https://sesacedu.store/search", "q", "query", fields={"q": ""})


def test_payload_probe_flags_raw_reflection(monkeypatch):
    monkeypatch.setattr(payload_probe.probe.core, "fetch", echo())
    out = payload_probe.run(T, [POINT], {"wordlist": pick("payload-reflect.txt"), "limit": "4", "methods": "GET"})
    assert out[0].verdict == "vuln" and "그대로 반사" in out[0].title


def test_payload_probe_flags_error_leak(monkeypatch):
    monkeypatch.setattr(payload_probe.probe.core, "fetch",
                        echo(transform=lambda v: "", extra="ORA-00933: SQL command not properly ended"))
    out = payload_probe.run(T, [POINT], {"wordlist": pick("payload-sql-error.txt"), "limit": "3", "methods": "GET"})
    assert out[0].verdict == "vuln" and "Oracle" in out[0].title
    assert "ORA-00933" in out[0].evidence


def test_payload_probe_potential_when_encoded(monkeypatch):
    def escape(v):
        return v.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;")
    monkeypatch.setattr(payload_probe.probe.core, "fetch", echo(transform=escape))
    out = payload_probe.run(T, [POINT], {"wordlist": pick("payload-reflect.txt"), "limit": "4", "methods": "GET"})
    assert out[0].verdict == "potential" and "필터" in out[0].evidence


def test_payload_probe_marker_alone_is_not_vuln(monkeypatch):
    """특수문자가 없는 표식만 돌아온 것은 '반사되는 자리'일 뿐 취약이 아니다."""
    monkeypatch.setattr(payload_probe.probe.core, "fetch",
                        echo(transform=lambda v: "".join(c for c in v if c not in "<>\"'&;`\\(){}")))
    out = payload_probe.run(T, [POINT], {"wordlist": pick("payload-reflect.txt"), "limit": "5", "methods": "GET"})
    assert out[0].verdict == "potential"


def test_payload_probe_safe_when_not_reflected(monkeypatch):
    monkeypatch.setattr(payload_probe.probe.core, "fetch", echo(transform=lambda v: ""))
    out = payload_probe.run(T, [POINT], {"wordlist": pick("payload-reflect.txt"), "limit": "3", "methods": "GET"})
    assert out[0].verdict == "safe"


def test_payload_probe_skips_post_by_default(monkeypatch):
    sent = []
    monkeypatch.setattr(payload_probe.probe.core, "fetch", lambda url, **k: sent.append(url) or Response(url, 200))
    post = Point("POST", "https://sesacedu.store/qna", "body", "form", fields={"body": ""})
    assert payload_probe.run(T, [post], {"wordlist": pick("payload-reflect.txt"), "limit": "3", "methods": "GET"}) == []
    assert sent == []


# ── 칼리 도구 결과 가져오기 ───────────────────────────────────

def test_import_ffuf_json():
    blob = json.dumps({"results": [{"url": "https://sesacedu.store/admin", "status": 200},
                                   {"url": "https://sesacedu.store/api/v1?page=1", "status": 200}]})
    r = import_tool_output.run(T, {"output": blob})
    paths = {urlsplit(p.url).path for p in r.points}
    assert paths == {"/admin", "/api/v1"} and "ffuf" in r.summary
    assert any(p.param == "page" for p in r.points)


def test_import_gobuster_text():
    out = "/admin               (Status: 200) [Size: 1234]\n/backup              (Status: 301) [Size: 0]\n"
    r = import_tool_output.run(T, {"output": out})
    assert {urlsplit(p.url).path for p in r.points} == {"/admin", "/backup"} and "gobuster" in r.summary


def test_import_nuclei_jsonl_makes_findings():
    line = json.dumps({"template-id": "tomcat-detect", "matched-at": "https://sesacedu.store/manager/html",
                       "info": {"name": "Tomcat Manager 노출", "severity": "high", "description": "막으세요"}})
    r = import_tool_output.run(T, {"output": line})
    assert r.findings[0].severity == "high" and "Tomcat Manager" in r.findings[0].title
    assert r.findings[0].location.endswith("/manager/html") and r.points


def test_import_plain_urls():
    r = import_tool_output.run(T, {"output": "https://sesacedu.store/a\nhttps://sesacedu.store/b?x=1\n"})
    assert {urlsplit(p.url).path for p in r.points} == {"/a", "/b"}


def test_import_rejects_junk():
    with pytest.raises(ValueError, match="읽을 수 있는 줄이 없습니다"):
        import_tool_output.run(T, {"output": "그냥 아무 말"})


def test_import_sends_nothing(monkeypatch):
    from dashboard import core
    monkeypatch.setattr(core, "fetch", lambda *a, **k: pytest.fail("요청을 보내면 안 된다"))
    import_tool_output.run(T, {"output": "https://sesacedu.store/a"})


# ── 화면 ──────────────────────────────────────────────────────

def test_imported_points_land_on_surface(app, client):
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹",
                                  "url": "https://sesacedu.store"})
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.post("/tools/run", data={
        "target_id": tid, "module_id": "import_tool_output",
        "output": "https://sesacedu.store/admin\nhttps://evil.example/x"}).get_data(as_text=True)
    assert "표면에 1개" in page and "범위 밖 1개 제외" in page
    assert "/admin" in client.get(f"/surface?target={tid}").get_data(as_text=True)


def test_wordlist_field_rejects_unknown_choice(app, client):
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹",
                                  "url": "https://sesacedu.store"})
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.post("/modules/content_discovery/run", data={
        "target_id": tid, "confirm": "yes", "wordlist": "/etc|passwd", "base": "/", "limit": "5"},
        follow_redirects=True).get_data(as_text=True)
    assert "고른 사전을 찾을 수 없습니다" in page


def test_payload_probe_notes_non_html_response(monkeypatch):
    """JSON 응답은 <> 가 살아 있어도 바로 XSS 는 아니다 — 근거에 적어 둔다."""
    def fetch(url, **kw):
        value = dict(parse_qs(urlsplit(url).query)).get("q", [""])[0]
        return Response(url, 200, [("Content-Type", "application/json")], json.dumps({"q": value}))
    monkeypatch.setattr(payload_probe.probe.core, "fetch", fetch)
    out = payload_probe.run(T, [POINT], {"wordlist": pick("payload-reflect.txt"), "limit": "4", "methods": "GET"})
    assert out[0].verdict == "vuln"
    assert "application/json" in out[0].evidence and "HTML 이 아닙니다" in out[0].evidence
