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
    for o in wordlists.available()["items"]:
        if o["label"].endswith(name):
            return o["value"]
    raise AssertionError(f"사전을 찾지 못했습니다: {name}")


# ── 사전 읽기 ─────────────────────────────────────────────────

def test_bundled_lists_are_found():
    labels = [o["label"] for o in wordlists.available()["items"]]
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
    assert any(o["label"].endswith("my.txt") for o in wordlists.available()["items"])
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


# ── SecLists 를 붙였을 때 ────────────────────────────────────────
# SecLists 는 Discovery/Web-Content/x.txt 처럼 2단계 깊이다. 예전에는 1단계만 봐서
# 루트를 가리키면 정작 쓸 목록이 통째로 안 보였다(Ai/prompts.txt 하나만 떴다).

@pytest.fixture
def seclists(tmp_path, monkeypatch):
    tree = {
        "Discovery/Web-Content/raft-small-words.txt": "admin\nlogin\n",
        "Discovery/Web-Content/common.txt": "a\n",
        "Discovery/DNS/subdomains.txt": "www\n",
        "Discovery/Variables/burp-parameter-names.txt": "id\n",
        "Fuzzing/LFI/LFI-Jhaddix.txt": "../\n",
        "Passwords/Common-Credentials/top-100.txt": "1234\n",
        "Usernames/top-usernames.txt": "root\n",
        "Ai/LLM_Testing/prompts.txt": "hi\n",
        ".git/hooks/ignore-me.txt": "nope\n",
    }
    for rel, body in tree.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")
    monkeypatch.setenv("DASH_WORDLISTS", str(tmp_path))
    return tmp_path


def _names(found):
    return [o["name"] for o in found["items"] if not o["label"].startswith("기본")]


def test_finds_lists_two_folders_deep(seclists):
    names = _names(wordlists.available())
    assert "Discovery/Web-Content/raft-small-words.txt" in names
    assert "Passwords/Common-Credentials/top-100.txt" in names


def test_skips_hidden_folders(seclists):
    assert ".git/hooks/ignore-me.txt" not in _names(wordlists.available())


@pytest.mark.parametrize("rel, want", [
    ("Discovery/Web-Content/raft-small-words.txt", "path"),
    ("Discovery/DNS/subdomains.txt", "subdomain"),
    ("Discovery/Variables/burp-parameter-names.txt", "param"),
    ("Fuzzing/LFI/LFI-Jhaddix.txt", "payload"),
    # 같은 LFI 묶음이라도 경로 목록은 경로다 — 안 가르면 경로 찾기 모듈에서 밀려난다
    ("seclists/LFI-gracefulsecurity-linux.txt", "path"),
    ("Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt", "path"),
    ("Passwords/Common-Credentials/top-100.txt", "password"),
    ("Usernames/top-usernames.txt", "username"),
    ("Ai/LLM_Testing/prompts.txt", "other"),
    ("web-common.txt", "path"),
    ("payload-reflect.txt", "payload"),
])
def test_classify_by_folder_then_name(rel, want):
    assert wordlists.classify(rel) == want


# ── 저장소에 담아 둔 SecLists 발췌 ─────────────────────────────
# 칼리에만 있으면 윈도에서 돌는 대시보드가 못 본다. 팀원마다 받게 하지 않고 세 개만 담았다.

@pytest.mark.parametrize("name", [
    "seclists/LFI-gracefulsecurity-linux.txt",
    "seclists/raft-small-directories.txt",
    "seclists/raft-small-files.txt",
])
def test_the_seclists_excerpt_is_bundled_and_counts_as_paths(name):
    """경로 목록으로 분류돼야 경로 찾기·퍼징 모듈의 '이 모듈용' 묶음에 뜬다."""
    one = next((o for o in wordlists.available("path")["items"] if o["name"] == name), None)
    assert one is not None, name
    assert one["purpose"] == "path" and one["match"]


def test_the_linux_list_holds_absolute_paths():
    """`traversal()` 이 맨 앞 / 를 떼므로 그대로 씨앗으로 쓸 수 있다."""
    lines, _ = wordlists.load(pick("seclists/LFI-gracefulsecurity-linux.txt"), limit=50)
    assert len(lines) == 50
    assert all(l.startswith("/") for l in lines)


def test_the_linux_list_brings_paths_our_seeds_do_not_have():
    """담아 둔 이유가 이것이다 — 없으면 이 파일은 저장소에 있을 값이 없다.

    `/etc/ssh/ssh_host_dsa_key`(서버 호스트 개인키)는 우리 씨앗에 없다. 거꾸로 이 목록은
    오래된 것이라 요즘 이름(`ssh_host_ed25519_key`)이 없다 — **넓다고 다 들어 있는 것은
    아니다.** 그래서 요즘 이름은 우리 씨앗에 직접 넣었다. 둘이 서로를 메운다.
    """
    theirs, _ = wordlists.load(pick("seclists/LFI-gracefulsecurity-linux.txt"), limit=5000)
    ours, _ = wordlists.load(pick("fs-seeds-sesacedu.txt"), limit=5000)
    theirs = {p.strip("/") for p in theirs}
    ours = {p.strip("/") for p in ours}
    assert "etc/ssh/ssh_host_dsa_key" in theirs - ours
    assert len(theirs - ours) > 500
    assert "etc/ssh/ssh_host_ed25519_key" in ours - theirs      # 우리가 메운 쪽


def test_matching_purpose_comes_first(seclists):
    groups = wordlists.available("path")["groups"]
    assert groups[0]["match"] and "경로" in groups[0]["label"]
    assert "이 모듈용" in groups[0]["label"]
    # 안 맞는 것도 남아 있어야 한다 — 아는 사람이 다른 걸 쓰려 할 때 막지 않는다
    assert any(not g["match"] for g in groups)
    assert any("비밀번호" in g["label"] for g in groups)


def test_no_purpose_means_no_marker(seclists):
    assert all("이 모듈용" not in g["label"] for g in wordlists.available()["groups"])


def test_size_is_shown(seclists):
    one = next(o for o in wordlists.available()["items"] if o["name"].endswith("raft-small-words.txt"))
    on_disk = (seclists / "Discovery/Web-Content/raft-small-words.txt").stat().st_size
    assert one["size"] == on_disk and one["size_label"].endswith("B")


def test_says_so_when_the_list_is_cut(seclists, monkeypatch):
    monkeypatch.setattr(wordlists, "MAX_FILES", 3)
    found = wordlists.available()
    assert found["cut"] and found["total"] > 3 and len(found["items"]) == 3


def test_picker_shows_groups_and_sizes(app, client, seclists):
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    html = client.get(f"/modules?target={tid}").get_data(as_text=True)
    assert "<optgroup" in html and "이 모듈용" in html
    assert "이름으로 찾기" in html          # 찾기 칸
    assert "data-size=" in html            # 크기
