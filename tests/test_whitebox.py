"""소스를 열어 놓고 짠 점검 — 화면으로는 잘 안 가는 길만 고른다(11-21 사용자 요청).

화면을 눌러 보는 테스트는 사람이 자주 가는 길만 지난다. 커버리지로 **안 지나간 줄**을
먼저 찾고, 그 조건문의 반대쪽을 여기서 고른다. 넷을 본다.

  ① 실행 결과 파일(runfiles)  마지막 파일 고르기, 없는 파일, 못 읽는 이름
  ② 준비물 검사(needs)        잘못 적은 META, 환경변수로만 확인되는 것
  ③ MCP 손(routes._mcp_*)     화면이 보는 문턱을 MCP 도 보는가, 거르개, 잘못된 값
  ④ 시간 읽기(mcp._ago)       띠 없는 옛 줄(UTC)과 지금 줄(KST)

②③ 에서 찾은 것: **MCP 는 needs 문턱을 안 봤다.** 토큰이 있어야 도는 모듈이 토큰 없이
돌아 '전부 401' 이라는 거짓 결과를 만들 수 있었다. routes._need_block 으로 화면과 묶었다.
"""
import json
import types

import pytest

from dashboard import mcp
from dashboard.db import get_db


# ── 거들개 ────────────────────────────────────────────────────

def add_target(client, name="사용자 웹", url="https://sesacedu.store", role="user_web"):
    client.post("/targets", data={"project": "sesacedu", "role": role, "name": name, "url": url},
                follow_redirects=True)


def token_of(app):
    with app.app_context():
        return mcp.token()


def rpc(client, app, method, params=None, key=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    r = client.post("/mcp", data=json.dumps(body), content_type="application/json",
                    headers={"Authorization": f"Bearer {key or token_of(app)}"})
    return r if r.status_code != 200 else json.loads(r.get_data(as_text=True))


def call(client, app, name, args=None):
    return rpc(client, app, "tools/call", {"name": name, "arguments": args or {}})["result"]


def text_of(result):
    return "\n".join(c["text"] for c in result["content"])


def fake_mod(mid="header_probe", name="보안 헤더 점검"):
    return types.SimpleNamespace(id=mid, name=name)


# ── ① 실행 결과 파일 ──────────────────────────────────────────

def test_the_last_run_file_is_the_biggest_number_not_the_last_name(app):
    """이름순으로 세면 자릿수가 넘어갈 때 뒤집힌다 — 0999 다음은 10000 이다."""
    from dashboard import runfiles
    t, mod = {"id": 1, "name": "사용자 웹", "url": "https://sesacedu.store"}, fake_mod()
    with app.app_context():
        for rid in (998, 999, 10000):
            runfiles.save(app, rid, t, mod, f"트리 {rid}")
        got = runfiles.find(app, t, mod.id)
    assert got is not None and "10000" in got.name
    assert "트리 10000" in runfiles.read(got)


def test_asking_for_one_run_that_left_no_file_gets_nothing(app):
    from dashboard import runfiles
    t, mod = {"id": 1, "name": "사용자 웹", "url": "x"}, fake_mod()
    with app.app_context():
        runfiles.save(app, 3, t, mod, "있다")
    assert runfiles.find(app, t, mod.id, run_id=4) is None      # 번호는 있는데 파일이 없다
    assert runfiles.find(app, t, "없는모듈") is None             # 폴더 자체가 없다


def test_a_file_that_is_gone_reads_as_none_instead_of_raising(app, tmp_path):
    from dashboard import runfiles
    assert runfiles.read(tmp_path / "없는파일.txt") is None


def test_run_ids_only_counts_names_that_are_numbers(app):
    """목록 화면이 '내용 보기' 를 붙일지 가리는 자리다. 사람이 손으로 넣어 둔 메모가 섞여도 넘어간다."""
    from dashboard import runfiles
    t, mod = {"id": 1, "name": "사용자 웹", "url": "x"}, fake_mod()
    with app.app_context():
        path = runfiles.save(app, 7, t, mod, "트리")
        (path.parent / "0메모.txt").write_text("사람이 둔 것", encoding="utf-8")
        assert runfiles.run_ids(app) == {7}


# ── ② 준비물 검사 ────────────────────────────────────────────

@pytest.mark.parametrize("bad, says", [
    ("줄", "dict"),                                                        # 모양이 아예 다르다
    ({"kind": "없는종류", "why": "a", "how": "b"}, "kind"),
    ({"kind": "env", "name": "X", "why": "a"}, "how"),                     # how 가 없다
    ({"kind": "auth_header", "why": "a", "how": "b"}, "name"),             # 이름 없는 헤더
])
def test_a_badly_written_need_is_refused_when_the_module_is_registered(bad, says):
    from dashboard import needs
    with pytest.raises(ValueError) as e:
        needs.validate([bad])
    assert says in str(e.value)


def test_an_env_need_is_ready_only_while_the_variable_has_something_in_it(monkeypatch):
    from dashboard import needs
    mod = types.SimpleNamespace(needs=needs.validate(
        [{"kind": "env", "name": "DASH_TEST_KEY", "why": "a", "how": "b"}]))
    monkeypatch.delenv("DASH_TEST_KEY", raising=False)
    assert needs.check(mod)[0]["ready"] is False
    monkeypatch.setenv("DASH_TEST_KEY", "   ")                             # 공백만은 빈 것으로 본다
    assert needs.check(mod)[0]["ready"] is False
    monkeypatch.setenv("DASH_TEST_KEY", "있다")
    assert needs.check(mod)[0]["ready"] is True
    assert needs.blocking(mod) == []


def test_what_we_cannot_check_never_blocks_a_run():
    """사람이 칼리에서 먼저 돌려야 하는 도구는 준비됐는지 알 수 없다 — 안내만 하고 막지 않는다."""
    from dashboard import needs
    mod = types.SimpleNamespace(needs=needs.validate(
        [{"kind": "tool", "name": "katana", "why": "a", "how": "b"}]))
    assert needs.check(mod)[0]["ready"] is None
    assert needs.blocking(mod) == []


# ── ③ MCP 손 ────────────────────────────────────────────────

def test_mcp_stops_at_the_same_threshold_the_screen_stops_at(client, app):
    """화이트박스로 찾은 것(11-21): MCP 에만 needs 검사가 없어 토큰 없이도 돌기 시작했다."""
    add_target(client)
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    out = call(client, app, "run_module", {"target_id": 1, "module_id": "sesacedu_material_traversal"})
    assert out["isError"] is True
    assert "인증 헤더" in text_of(out) and "Authorization" in text_of(out)
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0   # 돌지 않았다

    # 화면도 같은 말을 한다 — 한 자리(_need_block)에서 나온다
    page = client.post("/modules/sesacedu_material_traversal/run", data={"target_id": 1},
                       follow_redirects=True).get_data(as_text=True)
    assert "인증 헤더 Authorization 가 있어야 돌아갑니다" in page


def test_a_wrong_kind_of_value_is_refused_before_anything_runs(client, app):
    add_target(client)
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    out = call(client, app, "run_module",
               {"target_id": 1, "module_id": "authz_probe", "params": {"same_pct": "조금"}})
    assert out["isError"] is True and "숫자" in text_of(out)
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


def test_points_can_be_narrowed_the_way_the_screen_narrows_them(client, app):
    add_target(client)
    with app.app_context():
        db = get_db()
        for method, url, param in [("GET", "https://sesacedu.store/backend/lectures", "keyword"),
                                   ("GET", "https://sesacedu.store/courses", ""),
                                   ("POST", "https://sesacedu.store/backend/login", "email")]:
            db.execute("INSERT INTO points (target_id, method, url, param, place, source, first_seen, last_seen) "
                       "VALUES (1,?,?,?,'query','import','2026-11-21','2026-11-21')", [method, url, param])
        db.commit()

    everything = text_of(call(client, app, "points", {"target_id": 1}))
    assert everything.count("https://") == 3
    only_params = text_of(call(client, app, "points", {"target_id": 1, "params_only": True}))
    assert "courses" not in only_params and "keyword" in only_params
    only_backend = text_of(call(client, app, "points", {"target_id": 1, "contains": "/backend/log"}))
    assert "login" in only_backend and "lectures" not in only_backend
    assert text_of(call(client, app, "points", {"target_id": 1, "limit": 1})).count("https://") == 1


def test_findings_can_be_narrowed_by_severity_and_status(client, app):
    add_target(client)
    with app.app_context():
        db = get_db()
        run = db.execute("INSERT INTO runs (target_id, module_id, params, status, started_at) "
                         "VALUES (1,'header_probe','{}','done','2026-11-21T00:00:00')", []).lastrowid
        for title, sev, st in [("치명적인 것", "critical", "confirmed"), ("보통인 것", "medium", "open")]:
            db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, "
                       "status, created_at) VALUES (?,1,'header_probe',?,?,'/x','근거',?,'2026-11-21T00:00:00')",
                       [run, title, sev, st])
        db.commit()
    assert "치명적인 것" in text_of(call(client, app, "findings", {"severity": "critical"}))
    assert "보통인 것" not in text_of(call(client, app, "findings", {"severity": "critical"}))
    assert "보통인 것" in text_of(call(client, app, "findings", {"status": "open"}))
    assert "치명적인 것" in text_of(call(client, app, "findings", {"contains": "치명"}))


def test_asking_about_a_run_that_is_already_over_reads_the_record(client, app):
    """도는 동안은 jobs 목록에 있지만, 끝나고 목록에서 빠진 뒤에는 runs 표를 봐야 한다."""
    add_target(client)
    with app.app_context():
        db = get_db()
        rid = db.execute("INSERT INTO runs (target_id, module_id, params, status, sent, message, started_at) "
                         "VALUES (1,'header_probe','{}','done',12,'지점 3개 — 취약 1','2026-11-21T00:00:00')").lastrowid
        db.commit()
    got = text_of(call(client, app, "run_status", {"run_id": rid}))
    assert "done" in got and "보낸 요청 12" in got and "취약 1" in got
    assert call(client, app, "run_status", {"run_id": rid + 99})["isError"] is True


def test_the_tools_say_which_list_to_look_at_when_the_number_is_wrong(client, app):
    add_target(client)
    client.post("/connect/write", data={"on": "1"}, follow_redirects=True)
    assert "그런 대상이 없습니다" in text_of(call(client, app, "points", {"target_id": 99}))
    assert "그런 결과가 없습니다" in text_of(call(client, app, "finding", {"id": 99}))
    out = call(client, app, "set_status", {"id": 1, "status": "없는상태"})
    assert out["isError"] is True and "confirmed" in text_of(out)


def test_the_module_list_tells_which_ones_need_points_first(client, app):
    add_target(client)
    got = text_of(call(client, app, "modules", {"target_id": 1}))
    assert "probe" in got and "points" in got
    assert "surface_import" not in got            # 다른 모듈의 부품(hidden)은 안 내보낸다


# ── 대상 고르기(11-21 사용자 지적: 관리자 웹으로 바꿨는데 지점 목록이 사용자 웹) ──

def test_the_header_target_box_goes_somewhere_when_you_pick(client):
    """칸만 바뀌고 쪽이 그대로면, 고른 대상과 화면에 보이는 대상이 어긋난다.

    고르면 바로 가는 일은 app.js 가 한다 — 틀(`data-autosubmit`)과 손이 둘 다 있어야 한다.
    뒤로 가기 때 브라우저가 옛 선택을 되살리지 못하게 `autocomplete=off` 도 함께 본다.
    """
    add_target(client)
    page = client.get("/modules").get_data(as_text=True)
    assert 'id="target" name="target" data-autosubmit autocomplete="off"' in page
    js = client.get("/static/app.js").get_data(as_text=True)
    assert '[data-autosubmit]' in js and "el.form.submit()" in js


def test_the_module_popup_shows_the_points_of_the_target_you_picked(client, app):
    add_target(client, name="사용자 웹", url="https://sesacedu.store", role="user_web")
    add_target(client, name="관리자 웹", url="https://admin.sesacedu.store", role="admin_web")
    with app.app_context():
        db = get_db()
        for tid, url in ((1, "https://sesacedu.store/courses"),
                         (2, "https://admin.sesacedu.store/users")):
            db.execute("INSERT INTO points (target_id, method, url, param, place, source, first_seen, last_seen) "
                       "VALUES (?,'GET',?,'','path','import','2026-11-21','2026-11-21')", [tid, url])
        db.commit()

    # 표에는 주소에서 호스트를 뺀 경로만 적힌다
    panel = client.get("/modules/upload_probe/panel?target=2&partial=1").get_data(as_text=True)
    assert "/users" in panel and "/courses" not in panel
    assert "/courses" in client.get("/modules/upload_probe/panel?target=1&partial=1").get_data(as_text=True)
    # 모듈 화면이 그 팝업 주소를 target 과 함께 들고 있어야 한다
    page = client.get("/modules?target=2").get_data(as_text=True)
    assert "/modules/upload_probe/panel?target=2" in page


def test_the_risk_score_reads_as_a_gauge_not_a_cut_off_box(client, app):
    """점수만큼 바탕을 채우면 88 은 끝이, 40 은 글자 한가운데가 잘린 것처럼 보인다(11-21 사용자 지적)."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    chip = (root / "dashboard" / "templates" / "targets.html").read_text(encoding="utf-8")
    chip = chip.split('class="risk', 1)[1].split("</span>", 1)[0]
    assert chip.index("위험 {{ gr.risk }}") < chip.index("<i ")       # 막대는 글자 뒤(아래)에 깔린다
    assert "취약점 점수가 아닙니다" in chip                            # 무엇을 재는 숫자인지 말해 준다

    css = client.get("/static/style.css").get_data(as_text=True)
    bar = css.split(".risk i {", 1)[1].split("}", 1)[0]
    assert "bottom: 0" in bar and "height: 2px" in bar               # 바탕이 아니라 아래 눈금이다
    assert "top: 0" not in bar                                       # 위에서 아래까지 채우면 잘린 것처럼 보인다


# ── ④ 시간 읽기 ─────────────────────────────────────────────

def test_an_old_line_without_a_timezone_is_read_as_utc():
    """옛 줄은 sqlite 의 datetime('now')(UTC)로 적혔다. KST 로 읽으면 9시간이 어긋난다."""
    from datetime import datetime, timedelta, timezone
    naive = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(tzinfo=None).isoformat(" ")
    mins, said = mcp._ago(naive)
    assert 4 <= mins <= 6 and said == "5분 전"


@pytest.mark.parametrize("minutes, said", [(0, "방금"), (3, "3분 전"), (90, "1시간 전"), (60 * 30, "1일 전")])
def test_how_long_ago_is_said_in_the_biggest_unit_that_fits(minutes, said):
    from datetime import datetime, timedelta

    from dashboard.core import KST
    when = (datetime.now(KST) - timedelta(minutes=minutes)).isoformat()
    assert mcp._ago(when)[1] == said


def test_a_time_we_cannot_read_does_not_break_the_card():
    assert mcp._ago("어제쯤") == (None, "")
    assert mcp._ago(None) == (None, "")


def test_the_light_goes_quiet_after_a_while_instead_of_lying(client, app):
    """HTTP 라 연결이 이어져 있지 않다 — 오래 말이 없으면 '붙어 있다' 고 하면 안 된다."""
    rpc(client, app, "initialize", {"clientInfo": {"name": "Claude Code"}})
    assert client.get("/connect/state").get_json()["state"] == "live"
    with app.app_context():
        db = get_db()
        from datetime import datetime, timedelta

        from dashboard.core import KST
        old = (datetime.now(KST) - timedelta(minutes=mcp.FRESH_MIN + 1)).isoformat()
        db.execute("UPDATE mcp_calls SET called_at = ?", [old])
        db.commit()
    said = client.get("/connect/state").get_json()
    assert said["state"] == "idle"
    assert "아직" not in said["when"]                 # 붙은 적은 있다 — waiting 으로 돌아가지 않는다


def test_widening_the_lane_moves_cards_once_and_only_once(tmp_path):
    """띠를 넓히면 이미 놓인 카드도 같은 비율로 밀어야 전과 같은 띠에 남는다.

    두 번 밀면 또 어긋나므로, 한 번 했다는 표를 보고 다시 하지 않아야 한다.
    """
    from dashboard import create_app, db as db_mod
    cfg = {"TESTING": True, "SECRET_KEY": "t", "DATABASE": str(tmp_path / "m.sqlite3"),
           "RUNS_DIR": str(tmp_path / "runs"), "CSRF": False}
    app = create_app(cfg)
    with app.app_context():
        d = db_mod.get_db()
        d.execute("INSERT INTO targets (id, name, url, created_at) VALUES (1, 'T', 'http://127.0.0.1', '')")
        d.execute("INSERT INTO campaigns (id, target_id, name, created_at) VALUES (1, 1, ?, '')", ["c"])
        node = ("INSERT INTO campaign_nodes (campaign_id, kind, tactic, title, x, y, created_at) "
                "VALUES (1, 'finding', 'TA0007', ?, ?, 54, '')")
        d.execute(node, ["a", 260])
        d.execute(node, ["아직 안 놓음", -1])
        d.execute("DELETE FROM app_settings WHERE key = ?", ["lane_w_260_to_360"])
        d.commit()
        db_mod.init_db()
        moved = d.execute("SELECT x FROM campaign_nodes ORDER BY id").fetchall()
        assert moved[0]["x"] == 360                   # 띠 하나만큼이 그대로 띠 하나만큼으로
        assert moved[1]["x"] == -1                    # 자리를 안 정한 카드는 건드리지 않는다
        db_mod.init_db()
        again = d.execute("SELECT x FROM campaign_nodes ORDER BY id").fetchall()
        assert again[0]["x"] == 360                   # 두 번째에는 다시 밀지 않는다
