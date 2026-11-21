"""한 바퀴 — 조각이 아니라 **이어 붙인 길**을 본다(11-21 사용자 요청).

다른 테스트는 모듈 하나, 화면 하나를 따로 본다. 여기서는 사람이 실제로 하는 순서대로
끝에서 끝까지 간다. 가짜로 두는 것은 **바깥 서버 하나뿐**(core._opener)이고, 범위 검사·
인증 헤더 붙이기·요청 기록·백그라운드 실행·DB·화면은 전부 진짜를 지난다.

  ① 화면으로 한 바퀴   대상 등록 → 주소 모으기 → 지점 점검 → 결과 표 → 판정 → 보고서
  ② 보낸 것이 남는가   요청 기록·실행 기록에 그대로 남고, 대상 인증 헤더가 실려 나갔는가
  ③ MCP 로 한 바퀴     붙기 → 모듈 돌리기 → 결과 읽기 → 오탐 처리 → 캠페인 → 수사보드
  ④ 두 길이 같은가     같은 모듈을 화면으로·MCP 로 돌렸을 때 같은 모양이 남는가
  ⑤ 범위는 지켜지는가  범위 밖 주소는 모으지도, 보내지도 않는다
"""
import json
from email.message import Message

import pytest

from dashboard import core, mcp
from dashboard.db import get_db

FETCH = {"X-Requested-With": "fetch"}
SITE = "https://sesacedu.store"


# ── 가짜 바깥 서버 ────────────────────────────────────────────

class _Resp:
    def __init__(self, status, headers, body):
        self.status, self._body = status, body.encode()
        self.headers = Message()
        for k, v in headers:
            self.headers[k] = v

    def read(self, n=None):
        return self._body[:n] if n else self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def server(monkeypatch, handler):
    """core.fetch 아래 한 칸만 가짜로 바꾼다 — 범위 검사도 기록도 진짜 길을 지난다."""
    sent = []

    class Opener:
        def open(self, req, timeout=None):
            sent.append({"method": req.get_method(), "url": req.full_url,
                         "headers": dict(req.header_items())})
            return _Resp(*handler(req.full_url, req.get_method()))

    monkeypatch.setattr(core, "_opener", Opener())
    return sent


def plain_html(url, _method):
    """보안 헤더가 하나도 없는 화면 — 보안 헤더 점검이 취약으로 본다."""
    return 200, [("Content-Type", "text/html; charset=utf-8")], "<html><body>강의</body></html>"


# ── 거들개 ────────────────────────────────────────────────────

def add_target(client, name="사용자 웹", role="user_web"):
    client.post("/targets", data={"project": "sesacedu", "role": role, "name": name, "url": SITE},
                follow_redirects=True)


def collect(client, urls):
    client.post("/modules/surface_import/run", data={"target_id": 1, "urls": urls}, follow_redirects=True)


def point_ids(app, like=""):
    with app.app_context():
        return [r["id"] for r in get_db().execute(
            "SELECT id FROM points WHERE target_id = 1 AND url LIKE ?", ["%" + like + "%"])]


def rows(app, sql, args=()):
    with app.app_context():
        return get_db().execute(sql, args).fetchall()


def rpc(client, app, method, params=None):
    with app.app_context():
        key = mcp.token()
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    r = client.post("/mcp", data=json.dumps(body), content_type="application/json",
                    headers={"Authorization": f"Bearer {key}"})
    return r if r.status_code != 200 else json.loads(r.get_data(as_text=True))


def _docx_text(blob):
    """내려받은 Word 에서 글자만 뽑는다 — 표 안의 글자까지 본다."""
    import io

    from docx import Document
    doc = Document(io.BytesIO(blob))
    out = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        out += [c.text for row in t.rows for c in row.cells]
    return "\n".join(out)


def tool(client, app, name, args=None):
    out = rpc(client, app, "tools/call", {"name": name, "arguments": args or {}})["result"]
    return "\n".join(c["text"] for c in out["content"]), out.get("isError") is True


# ── ① 화면으로 한 바퀴 ────────────────────────────────────────

def test_from_registering_a_target_to_the_report(app, client, monkeypatch):
    """사람이 하는 순서 그대로: 등록 → 주소 모으기 → 점검 → 판정 → 보고서."""
    add_target(client)
    collect(client, f"{SITE}/courses\n{SITE}/backend/lectures?keyword=a")
    assert len(point_ids(app)) >= 2

    server(monkeypatch, plain_html)
    ids = point_ids(app, "/courses")
    r = client.post("/surface/probe", headers=FETCH,
                    data={"target_id": 1, "module_id": "header_probe", "point": ids})
    assert r.json["ok"]

    # 판정이 지점에 붙고, 취약은 결과 한 줄이 된다
    checks = rows(app, "SELECT * FROM point_checks WHERE module_id = 'header_probe'")
    assert len(checks) == 1 and checks[0]["verdict"] == "vuln"
    found = rows(app, "SELECT * FROM findings")
    assert len(found) == 1 and found[0]["status"] == "open"
    assert found[0]["exchange_id"], "결과에 그때 받은 응답이 붙어 있어야 다시 볼 수 있다"

    page = client.get("/").get_data(as_text=True)
    assert found[0]["title"] in page and "/courses" in page

    # 확인됨으로 올리면 보고서에 그대로 실린다
    client.post(f'/findings/{found[0]["id"]}/status', data={"status": "confirmed"})
    md = client.get("/report/1.md").get_data(as_text=True)
    data = client.get("/report/1.json").get_json()
    assert found[0]["title"] in md and "/courses" in md
    # 위치는 코드로 적는다 — 링크가 되면 눌렀을 때 401·JSON 이 뜬다(11-21 사용자 지적)
    assert f'| `{found[0]["location"]}` |' in md
    assert "눌러 보는 링크가 아닙니다" in md
    assert [f["title"] for f in data["findings"]] == [found[0]["title"]]

    # 내려받기 단추가 주는 것은 Word 다(11-21 사용자 지시)
    doc = client.get("/report/1.docx")
    assert doc.status_code == 200 and doc.get_data()[:2] == b"PK"      # zip 으로 시작하는 진짜 docx
    assert "wordprocessingml" in doc.headers["Content-Type"]
    assert ".docx" in doc.headers["Content-Disposition"]
    text = _docx_text(doc.get_data())
    # 팀 결과보고서 양식의 절 이름·표가 그대로 나온다(01_제출물/결과보고서_양식)
    assert "3-2. 위험도 적용 결과" in text and "4-2. 대상별 취약점 요약" in text
    assert "5. Part A. 진단 상세 결과" in text and "5-1. 진단 방법" in text
    assert "V-01" in text and "V-01-1" in text and "A-01" in text and "외부(DMZ)" in text
    assert found[0]["title"] in text and "대표 PoC" in text
    assert "[ ]" in text                       # 사람이 채울 자리는 비워 두고 보여 준다

    # 오탐으로 내리면 보고서에서 빠진다 — 지워서가 아니라 상태로 가린다
    client.post(f'/findings/{found[0]["id"]}/status', data={"status": "false_positive"})
    assert client.get("/report/1.json").get_json()["findings"] == []
    assert len(rows(app, "SELECT * FROM findings")) == 1


def test_a_false_positive_drops_out_of_the_boards_but_stays_counted(app, client, monkeypatch):
    """오탐은 숫자 판(OWASP·처리 상태)에서 빠지되, 처리한 기록으로는 남는다."""
    add_target(client)
    collect(client, f"{SITE}/courses")
    server(monkeypatch, plain_html)
    client.post("/surface/probe", headers=FETCH,
                data={"target_id": 1, "module_id": "header_probe", "point": point_ids(app)})
    fid = rows(app, "SELECT id FROM findings")[0]["id"]

    before, _ = tool(client, app, "coverage")
    client.post(f"/findings/{fid}/status", data={"status": "false_positive"})
    after, _ = tool(client, app, "coverage")
    assert before != after, "오탐으로 내렸는데 판이 그대로면 숫자를 믿을 수 없다"
    assert "점검·없음" in after                       # 돌긴 돌았고 남은 것이 없다는 자리로 내려간다
    assert rows(app, "SELECT status FROM findings")[0]["status"] == "false_positive"


# ── ② 보낸 것이 남는가 ────────────────────────────────────────

def test_what_we_sent_is_kept_with_the_token_we_sent_it_with(app, client, monkeypatch):
    add_target(client)
    collect(client, f"{SITE}/courses")
    client.post("/targets/1/headers", data={"headers": "Authorization: Bearer 테스트토큰"},
                follow_redirects=True)
    sent = server(monkeypatch, plain_html)
    client.post("/surface/probe", headers=FETCH,
                data={"target_id": 1, "module_id": "header_probe", "point": point_ids(app)})

    assert sent and all(s["url"].startswith(SITE) for s in sent)
    assert any("테스트토큰" in (s["headers"].get("Authorization") or "") for s in sent), \
        "대상에 넣어 둔 인증 헤더가 실제로 실려 나가야 한다"

    run = rows(app, "SELECT * FROM runs ORDER BY id DESC")[0]
    assert run["status"] == "done" and run["sent"] == len(sent)
    kept = rows(app, "SELECT * FROM exchanges WHERE run_id = ?", [run["id"]])
    assert len(kept) == len(sent)
    assert "테스트토큰" in kept[0]["req_headers"]      # 가리지 않고 그대로 남긴다(11-07 사용자 지시)

    page = client.get("/history").get_data(as_text=True)
    assert "/courses" in page
    assert client.get(f'/jobs/{run["id"]}/exchanges').status_code == 200


# ── ③ MCP 로 한 바퀴 ─────────────────────────────────────────

def test_an_ai_tool_can_do_the_same_round_through_mcp(app, client, monkeypatch):
    """붙기 → 모듈 → 결과 → 판정 → 캠페인. 화면을 한 번도 누르지 않는다(쓰기 스위치만 사람이 켠다)."""
    add_target(client)
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    hello = rpc(client, app, "initialize", {"protocolVersion": "2025-06-18",
                                            "clientInfo": {"name": "Claude Code", "version": "1.0"}})
    assert hello["result"]["serverInfo"]["name"] == "ttalkkak"
    names = {t["name"] for t in rpc(client, app, "tools/list")["result"]["tools"]}
    assert {"run_module", "findings", "set_status", "make_campaign"} <= names

    said, bad = tool(client, app, "run_module",
                     {"target_id": 1, "module_id": "surface_import",
                      "params": {"urls": f"{SITE}/courses"}})
    assert not bad and "run_id" in said
    status, _ = tool(client, app, "run_status")
    assert "surface_import" in status
    listed, _ = tool(client, app, "points", {"target_id": 1})
    assert "/courses" in listed

    server(monkeypatch, plain_html)
    said, bad = tool(client, app, "run_module",
                     {"target_id": 1, "module_id": "header_probe", "points": point_ids(app)})
    assert not bad, said
    found, _ = tool(client, app, "findings", {"target_id": 1})
    fid = rows(app, "SELECT id FROM findings")[0]["id"]
    assert str(fid) in found
    detail, _ = tool(client, app, "finding", {"id": fid})
    assert "[근거]" in detail and "/courses" in detail

    # 하나는 확인됨으로 올리고 캠페인을 만든다 — 보드에서 바로 보여야 한다
    said, bad = tool(client, app, "set_status", {"id": fid, "status": "confirmed", "note": "직접 다시 보냄"})
    assert not bad
    made, bad = tool(client, app, "make_campaign", {"target_id": 1, "name": "발표용 시나리오"})
    assert not bad and "캠페인 #1" in made
    board = client.get("/scenario?target=1").get_data(as_text=True)
    assert "발표용 시나리오" in board

    # 바깥에서 들어온 손은 기록으로 남는다
    assert "run_module" in client.get("/connect").get_data(as_text=True)
    assert client.get("/connect/state").get_json()["state"] == "live"


# ── ④ 두 길이 같은가 ─────────────────────────────────────────

def test_the_screen_and_mcp_leave_the_same_shape_behind(app, client, monkeypatch):
    """같은 모듈을 두 길로 돌린다. 결과가 다르면 둘 중 하나는 거짓말이다."""
    add_target(client)
    collect(client, f"{SITE}/courses")
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    server(monkeypatch, plain_html)
    ids = point_ids(app)

    client.post("/surface/probe", headers=FETCH,
                data={"target_id": 1, "module_id": "header_probe", "point": ids})
    by_screen = rows(app, "SELECT * FROM point_checks")[0]
    tool(client, app, "run_module", {"target_id": 1, "module_id": "header_probe", "points": ids})
    checks = rows(app, "SELECT * FROM point_checks")

    assert len(checks) == 1, "같은 지점·같은 모듈은 덮어쓴다 — 돌릴 때마다 줄이 늘면 안 된다"
    assert checks[0]["verdict"] == by_screen["verdict"] and checks[0]["evidence"] == by_screen["evidence"]
    assert len(rows(app, "SELECT * FROM runs")) == 3          # 수집 1 + 점검 2, 둘 다 실행으로 남는다
    assert len(rows(app, "SELECT * FROM findings")) == 1, "같은 자리의 같은 문제는 한 줄로 센다"


# ── ⑤ 범위는 지켜지는가 ──────────────────────────────────────

def test_an_address_outside_the_scope_is_neither_collected_nor_sent(app, client, monkeypatch):
    add_target(client)
    collect(client, f"{SITE}/courses\nhttps://www.google.com/search?q=a")
    urls = [r["url"] for r in rows(app, "SELECT url FROM points")]
    assert all("google" not in u for u in urls)

    sent = server(monkeypatch, plain_html)
    with app.app_context():
        with pytest.raises(Exception) as e:
            core.fetch("https://www.google.com/")
    assert "범위" in str(e.value)
    assert sent == [], "범위 밖이면 요청 자체가 나가지 않는다"
