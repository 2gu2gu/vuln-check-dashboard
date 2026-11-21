"""딸깍이를 MCP 서버로 연 자리(11-21 사용자 결정).

여기서 보는 것은 셋이다.
  ① 말이 통하는가       — initialize · tools/list · tools/call 이 MCP 모양으로 오가는가
  ② 아무나 못 들어오는가 — 토큰이 없으면 거절, 쓰기 스위치가 꺼져 있으면 쓰기 도구는 거절
  ③ 화면과 같은 길인가   — MCP 로 바꾼 상태·만든 캠페인이 화면에서 보는 것과 같은 DB 에 남는가
"""
import json

import pytest

from dashboard.db import get_db


def add_target(client, url="https://sesacedu.store", name="사용자 웹"):
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": name, "url": url},
                follow_redirects=True)


def token_of(app):
    from dashboard import mcp
    with app.app_context():
        return mcp.token()


def rpc(client, app, method, params=None, rid=1, key=None):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    r = client.post("/mcp", data=json.dumps(body), content_type="application/json",
                    headers={"Authorization": f"Bearer {key or token_of(app)}"})
    return r if r.status_code != 200 else json.loads(r.get_data(as_text=True))


def call(client, app, name, args=None):
    out = rpc(client, app, "tools/call", {"name": name, "arguments": args or {}})
    return out["result"]


def text_of(result):
    return "\n".join(c["text"] for c in result["content"])


def seed_finding(app, tid, **kw):
    """결과 한 줄을 직접 넣는다 — MCP 쪽만 보려고 모듈을 돌리지는 않는다."""
    with app.app_context():
        db = get_db()
        run = db.execute("INSERT INTO runs (target_id, module_id, params, status, started_at) "
                         "VALUES (?, 'header_probe', '{}', 'done', '2026-11-21T00:00:00')", [tid]).lastrowid
        row = {"title": "테스트 결과", "severity": "high", "location": "/x", "evidence": "근거",
               "status": "confirmed", "module_id": "header_probe", **kw}
        cur = db.execute(
            "INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,'2026-11-21T00:00:00')",
            [run, tid, row["module_id"], row["title"], row["severity"], row["location"], row["evidence"], row["status"]])
        db.commit()
        return cur.lastrowid


# ── ① 말이 통하는가 ────────────────────────────────────────────

def test_initialize_speaks_the_version_the_client_asked_for(client, app):
    out = rpc(client, app, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}})
    r = out["result"]
    assert r["protocolVersion"] == "2025-03-26"        # 클라이언트 쪽 판을 따라 적는다
    assert r["serverInfo"]["name"] == "ttalkkak"
    assert "tools" in r["capabilities"]


def test_tools_list_tells_what_each_one_sees(client, app):
    tools = rpc(client, app, "tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    assert {"targets", "points", "findings", "finding", "run_module", "set_status",
            "cve_candidates", "make_campaign"} <= names
    for t in tools:
        assert t["description"].strip() and t["inputSchema"]["type"] == "object"
        assert "write" not in t                        # 우리끼리 쓰는 칸은 밖으로 내보내지 않는다


def test_a_notification_gets_no_answer(client, app):
    r = client.post("/mcp", data=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                    content_type="application/json",
                    headers={"Authorization": f"Bearer {token_of(app)}"})
    assert r.status_code == 202 and not r.get_data()


def test_an_unknown_tool_comes_back_as_an_error_not_a_crash(client, app):
    assert call(client, app, "없는도구")["isError"] is True


# ── ② 아무나 못 들어오는가 ──────────────────────────────────────

def test_no_token_no_entry(client):
    r = client.post("/mcp", data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                    content_type="application/json")
    assert r.status_code == 401
    assert "토큰" in r.get_data(as_text=True)


def test_a_wrong_token_is_the_same_as_none(client, app):
    r = rpc(client, app, "tools/list", key="아니다")
    assert r.status_code == 401


def test_write_tools_are_refused_while_the_switch_is_off(client, app):
    """모듈을 돌리는 입구다. 기본은 꺼져 있고, 화면에서 사람이 켠다."""
    add_target(client)
    out = call(client, app, "set_status", {"id": 1, "status": "confirmed"})
    assert out["isError"] is True and "연결" in text_of(out)


def test_the_switch_on_the_page_opens_them(client, app):
    add_target(client)
    fid = seed_finding(app, 1, status="open")
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    out = call(client, app, "set_status", {"id": fid, "status": "false_positive", "note": "화면 틀이었다"})
    assert out.get("isError") is not True
    with app.app_context():
        row = get_db().execute("SELECT status, evidence FROM findings WHERE id = ?", [fid]).fetchone()
    assert row["status"] == "false_positive"
    assert "화면 틀이었다" in row["evidence"]           # 까닭이 근거에 남는다


def test_the_page_shows_the_line_to_paste(client, app):
    page = client.get("/connect").get_data(as_text=True)
    assert "claude mcp add ttalkkak" in page and token_of(app) in page


def test_a_new_token_breaks_the_old_one(client, app):
    old = token_of(app)
    client.post("/connect/new-token", data={}, follow_redirects=True)
    assert token_of(app) != old
    assert rpc(client, app, "tools/list", key=old).status_code == 401


# ── ③ 화면과 같은 길인가 ────────────────────────────────────────

def test_reading_tools_work_without_the_switch(client, app):
    add_target(client)
    fid = seed_finding(app, 1)
    assert "sesacedu.store" in text_of(call(client, app, "targets"))
    assert "테스트 결과" in text_of(call(client, app, "findings", {"target_id": 1}))
    assert "근거" in text_of(call(client, app, "finding", {"id": fid}))
    assert "OWASP" in text_of(call(client, app, "coverage")) or "A01" in text_of(call(client, app, "coverage"))


def test_a_probe_module_without_points_says_so_instead_of_running(client, app):
    add_target(client)
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    out = call(client, app, "run_module", {"target_id": 1, "module_id": "reflection_check"})
    assert out["isError"] is True and "지점" in text_of(out)


def test_an_unknown_module_says_which_list_to_look_at(client, app):
    add_target(client)
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    out = call(client, app, "run_module", {"target_id": 1, "module_id": "없는모듈"})
    assert out["isError"] is True and "modules" in text_of(out)


def test_make_campaign_lays_the_findings_out_in_tactic_columns(client, app):
    """사용자 제안(11-21): 점검으로 나온 것을 시나리오 한 벌로 묶어 보고서에 올린다."""
    add_target(client)
    seed_finding(app, 1, title="민감 파일 읽기", module_id="traversal_probe", severity="critical")
    seed_finding(app, 1, title="서버 정보 노출", module_id="header_probe",
                 evidence="Server: Apache Tomcat/10.1.1")
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    out = text_of(call(client, app, "make_campaign", {"target_id": 1, "name": "발표용"}))
    assert "캠페인 #1" in out and "발표용" in out
    assert "민감 파일 읽기" in out and "서버 정보 노출" in out
    assert "/scenario?target=1" in out                 # 보드로 바로 간다
    with app.app_context():
        db = get_db()
        n = db.execute("SELECT COUNT(*) FROM campaign_nodes WHERE campaign_id = 1").fetchone()[0]
        kinds = {r[0] for r in db.execute("SELECT DISTINCT kind FROM campaign_nodes WHERE campaign_id = 1")}
    assert n >= 2 and "finding" in kinds
    assert "observed" in kinds                         # 근거에 보인 Tomcat 10.1.1 도 올라간다


def test_make_campaign_groups_the_same_title_and_takes_the_worst_first(client, app):
    """확인됨으로 만들면 사용자 웹만 156건이었다 — 보드가 못 쓰게 된다(11-22 사용자 지적).

    같은 제목은 한 노드로 묶고(후보 패널이 하는 것과 같다), 심각도로 고르고, 가짓수에 상한을 둔다.
    """
    add_target(client)
    for i in range(7):
        seed_finding(app, 1, title="요청 수 제한 없음", module_id="rate_limit_probe", severity="medium",
                     location=f"https://sesacedu.store/backend/a{i}")
    seed_finding(app, 1, title="민감 파일 읽기", module_id="traversal_probe", severity="critical")
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)

    out = text_of(call(client, app, "make_campaign", {"target_id": 1, "name": "묶기"}))
    assert "외 6곳" in out                                  # 일곱 건이 한 줄로
    with app.app_context():
        n = get_db().execute("SELECT COUNT(*) FROM campaign_nodes WHERE campaign_id = 1 AND kind = 'finding'"
                             ).fetchone()[0]
    assert n == 2                                           # 제목 두 가지 = 노드 두 개

    # 심각도로 좁히면 그것만, 상한을 걸면 심한 것부터
    out = text_of(call(client, app, "make_campaign",
                       {"target_id": 1, "name": "크리티컬만", "severity": ["critical"]}))
    assert "민감 파일 읽기" in out and "요청 수 제한 없음" not in out
    out = text_of(call(client, app, "make_campaign", {"target_id": 1, "name": "한 가지만", "top": 1}))
    assert "민감 파일 읽기" in out and "1가지는 뺐습니다" in out


def test_make_campaign_says_what_to_do_when_nothing_is_confirmed(client, app):
    add_target(client)
    seed_finding(app, 1, status="open")
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    out = call(client, app, "make_campaign", {"target_id": 1})
    assert out["isError"] is True and "open" in text_of(out)


def test_cve_candidates_reads_versions_out_of_the_evidence(client, app):
    add_target(client)
    seed_finding(app, 1, title="서버 정보 노출", module_id="header_probe",
                 evidence="Server: Apache Tomcat/10.1.1 이 그대로 나옵니다")
    out = text_of(call(client, app, "cve_candidates", {"target_id": 1}))
    assert "Apache Tomcat 10.1.1" in out
    assert "NVD" in out                                # 아직 안 물어봤다고 알려 준다


def test_the_calls_are_written_down(client, app):
    add_target(client)
    call(client, app, "targets")
    page = client.get("/connect").get_data(as_text=True)
    assert "targets" in page


@pytest.mark.parametrize("name", ["targets", "points", "modules", "findings", "finding", "coverage",
                                  "run_status", "run_module", "set_status", "cve_candidates", "make_campaign"])
def test_every_listed_tool_is_actually_wired(name):
    """목록에만 있고 손이 없는 도구가 생기지 않게."""
    from dashboard import mcp
    from dashboard.routes import MCP_TOOLS
    assert name in MCP_TOOLS and name in mcp.BY_NAME
    assert set(MCP_TOOLS) == set(mcp.BY_NAME)


# ── 붙었는지 보이는가(11-21 사용자 지적: 연결이 된 건지 직관적으로 안 보인다) ──

def test_the_page_says_nobody_is_connected_yet(client):
    page = client.get("/connect").get_data(as_text=True)
    assert "아직 아무도 안 붙었습니다" in page
    assert 'data-state="waiting"' in page


def test_the_handshake_turns_the_light_on_and_names_the_tool(client, app):
    rpc(client, app, "initialize", {"protocolVersion": "2025-06-18",
                                    "clientInfo": {"name": "Claude Code", "version": "1.0.2"}})
    st = client.get("/connect/state").get_json()
    assert st["state"] == "live" and st["client"] == "Claude Code 1.0.2"
    page = client.get("/connect").get_data(as_text=True)
    assert 'data-state="live"' in page and "Claude Code 1.0.2" in page


def test_the_light_does_not_count_the_handshake_as_a_call(client, app):
    """'몇 번 불렸나' 는 도구를 부른 수다 — 인사까지 세면 아무것도 안 했는데 1 이 된다."""
    rpc(client, app, "initialize", {"clientInfo": {"name": "t"}})
    assert client.get("/connect/state").get_json()["calls"] == 0
    call(client, app, "targets")
    assert client.get("/connect/state").get_json()["calls"] == 1


def test_a_tool_that_does_not_say_its_name_still_shows_up(client, app):
    rpc(client, app, "initialize", {})
    assert client.get("/connect/state").get_json()["client"] == "이름을 안 밝힌 도구"


def test_the_tab_is_called_mcp(client):
    page = client.get("/connect").get_data(as_text=True)
    assert ">MCP\n" in page or ">MCP<" in page or "MCP </a>" in page.replace("\n", " ")
