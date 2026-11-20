"""결과 탭 위쪽 그림(11-20 기획 1단계)과 점검 기준(KISA·OWASP 2025) 붙이기."""
import pytest

from dashboard import standards, stats
from dashboard.db import get_db
from tests.test_app import add_target, target_id


# ── 점검 기준 ─────────────────────────────────────────────────

def test_kisa_table_has_the_21_items_and_known_owasp_keys():
    assert len(standards.KISA) == 21
    assert {k for _, k in standards.KISA.values()} <= set(standards.OWASP_NAME)


def test_unknown_kisa_code_is_refused():
    """보고서 양식에 없는 코드를 적으면 모듈이 안 올라간다 — 보고서와 말이 갈라진다."""
    with pytest.raises(ValueError, match="ZZ"):
        standards.check_kisa(["SI", "ZZ"])


def test_owasp_follows_the_kisa_codes():
    assert standards.owasp_of(["XS", "SI", "FD"]) == ["A05", "A01"]


def test_vuln_finding_modules_carry_kisa_codes(app):
    """취약점을 찾는 모듈은 다 코드를 달고 있어야 2단계(OWASP 점검 현황)가 맞게 나온다."""
    mods = app.config["MODULES"] if "MODULES" in app.config else None
    from dashboard.registry import load_catalog
    catalog = load_catalog()[0] if mods is None else mods
    tagged = {m.id: m.kisa for m in catalog.values() if m.vuln != "기타"}
    assert tagged and all(tagged.values()), tagged
    assert catalog["sesacedu_lecture_sqli"].owasp == ["A05"]


# ── 집계 ──────────────────────────────────────────────────────

def _finding(db, tid, severity, status="open"):
    run = db.execute("INSERT INTO runs (target_id, module_id, started_at, status) VALUES (?, 'm', '2026-11-20', 'done')",
                     [tid]).lastrowid
    db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, status, created_at) "
               "VALUES (?, ?, 'm', 't', ?, ?, '2026-11-20')", [run, tid, severity, status])


@pytest.fixture
def two_targets(app, client):
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    add_target(client, "https://admin.sesacedu.store", name="관리자 웹", role="admin_web")
    a, b = target_id(app, "https://sesacedu.store"), target_id(app, "https://admin.sesacedu.store")
    with app.app_context():
        db = get_db()
        for sev in ["critical", "high", "high", "low"]:
            _finding(db, a, sev)
        _finding(db, a, "medium", "fixed")            # 조치됨 — 미조치에서 빠진다
        _finding(db, a, "high", "confirmed")
        _finding(db, b, "medium")
        db.commit()
    return a, b


def _overview(app):
    with app.app_context():
        db = get_db()
        return stats.overview(db, db.execute("SELECT * FROM targets ORDER BY id").fetchall())


def test_overview_counts_open_findings_per_target(app, two_targets):
    a, b = two_targets
    ov = _overview(app)
    rows = {r["target"]["id"]: r for r in ov["rows"]}
    # '확인됨' 도 아직 조치 전이라 미조치에 든다. 조치됨은 빠진다.
    assert rows[a]["counts"] == {"critical": 1, "high": 3, "medium": 0, "low": 1, "info": 0}
    assert rows[a]["total"] == 5 and rows[b]["total"] == 1
    assert ov["totals"]["high"] == 3 and ov["total"] == 6
    assert [g["severity"] for g in rows[a]["segments"]] == ["critical", "high", "low"]


def test_axis_ends_on_a_round_tick(app, two_targets):
    """막대가 축 끝을 넘지 않고, 눈금은 0·1·2… 처럼 고른 간격이다."""
    ov = _overview(app)
    ticks = [t["n"] for t in ov["ticks"]]
    assert ticks[0] == 0 and ticks[-1] >= 5 and len(set(b - a for a, b in zip(ticks, ticks[1:]))) == 1
    assert all(sum(g["pct"] for g in r["segments"]) <= 100 for r in ov["rows"])


def test_reviewed_share_counts_everything_not_open(app, two_targets):
    ov = _overview(app)
    assert ov["reviewed_pct"] == round(2 * 100 / 7) and ov["unreviewed"] == 5


def test_results_page_draws_the_report_style_overview(client, two_targets):
    a, b = two_targets
    page = client.get(f"/?target={a}").get_data(as_text=True)
    assert "점검 현황" in page and "위험도별 건수" in page and "대상별 위험도 분포" in page
    assert "대상별 취약점 요약" in page and "<tfoot>" in page
    # 막대 칸과 표 칸은 아래 목록을 그 대상·심각도로 거르는 링크다
    assert f'href="/?target={b}&amp;severity=medium"' in page
    assert 'title="사용자 웹 · High 3건">3</a>' in page


def test_practice_targets_are_left_out_of_the_overview(app, client):
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    add_target(client, "http://127.0.0.1:5051", name="연습", role="practice")
    page = client.get(f"/?target={target_id(app, 'https://sesacedu.store')}").get_data(as_text=True)
    overview = page.split('id="ov-title"', 1)[1].split("— 결과 목록", 1)[0]
    assert "사용자 웹" in overview and "연습" not in overview.replace("연습용 제외", "")


# ── 진단 통계(11-20 추가) ──────────────────────────────────────

def _tagged_finding(db, tid, module_id, severity, status="open"):
    run = db.execute("INSERT INTO runs (target_id, module_id, started_at, status) VALUES (?, ?, '2026-11-20', 'done')",
                     [tid, module_id]).lastrowid
    db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, status, created_at) "
               "VALUES (?, ?, ?, 't', ?, ?, '2026-11-20')", [run, tid, module_id, severity, status])


@pytest.fixture
def typed(app, client):
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    tid = target_id(app, "https://sesacedu.store")
    with app.app_context():
        db = get_db()
        _tagged_finding(db, tid, "sesacedu_lecture_sqli", "critical")         # SI → A05
        _tagged_finding(db, tid, "payload_probe", "medium")                    # XS·SI → 첫 코드 XS → A05
        _tagged_finding(db, tid, "sesacedu_material_traversal", "high")        # FD → A01
        _tagged_finding(db, tid, "port_check", "medium")                       # 코드 없음 → 분류 없음
        _tagged_finding(db, tid, "http_security_headers", "low", "fixed")      # 조치됨 — 미조치에서 빠짐
        db.execute("INSERT INTO runs (target_id, module_id, started_at, status) VALUES (?, 'tech_fingerprint', 'x', 'done')", [tid])
        db.commit()
    return tid




def test_findings_are_counted_once_by_their_first_kisa_code(app, typed):
    from dashboard import routes
    with app.test_request_context():
        mods = routes._modules()
        db = get_db()
        bd = stats.breakdown(db, db.execute("SELECT * FROM targets").fetchall(), mods)
    ow = {r["key"]: r for r in bd["owasp"]}
    assert ow["A05"]["total"] == 2 and ow["A01"]["total"] == 1
    assert bd["unclassified"]["total"] == 1
    # 합이 미조치 전체와 맞아야 한다 — 두 번 세지 않는다
    assert sum(r["total"] for r in bd["owasp"]) + bd["unclassified"]["total"] == 4
    kisa = {r["code"]: r for r in bd["kisa"]}
    assert kisa["SI"]["state"] == "found" and kisa["XS"]["found"] == 1 and kisa["FD"]["found"] == 1
    # 돌렸는데 결과가 없으면 '점검·없음', 모듈이 없으면 '모듈 없음'
    assert kisa["IL"]["state"] == "clear" and kisa["CF"]["state"] == "none"
    assert ow["A03"]["state"] == "none"
    status = {g["status"]: g["n"] for g in bd["status"]}
    assert status == {"open": 4, "confirmed": 0, "fixed": 1, "false_positive": 0}


def test_activity_totals(app, typed):
    with app.app_context():
        db = get_db()
        act = stats.activity(db, db.execute("SELECT * FROM targets").fetchall())
    assert act["findings"] == 5 and act["open"] == 4 and act["runs"] == 6 and act["modules_used"] == 6


def test_results_page_shows_totals_and_breakdowns(client, typed):
    page = client.get(f"/?target={typed}").get_data(as_text=True)
    for word in ("전체 결과", "모듈 실행", "보낸 요청", "모은 엔드포인트",
                 "취약점 유형별", "처리 상태별", "진단 일정", "21항목 점검 현황"):
        assert word in page, word
    assert 'class="kisa-cell cov-found"' in page and 'class="kisa-cell cov-none"' in page
    assert "built-in method" not in page  # kisa_cover.clear 가 dict.clear 로 읽히던 실수


# ── 진단 일정(11-20) ──────────────────────────────────────────

def test_calendar_covers_the_project_weeks_and_marks_deadlines(app, typed):
    from datetime import date
    sched = {"start": "2026-10-12", "end": "2026-11-23", "weeks": 7,
             "marks": [{"date": "2026-11-02", "label": "중간보고", "kind": "mid", "short": "중간"},
                       {"date": "2026-11-23", "label": "최종보고회", "kind": "final", "short": "최종"}]}
    with app.app_context():
        db = get_db()
        cal = stats.calendar(db, db.execute("SELECT * FROM targets").fetchall(), sched, today=date(2026, 11, 20))
    days = {c["date"]: c for w in cal["weeks"] for c in w["cells"]}
    # 1주차 = 10-12(월) 주, 월~일 7주. 최종보고회 11-23(월)은 7주차 첫날이고 그 뒤는 기간 밖(사용자 결정 11-20)
    assert len(cal["weeks"]) == 7 and min(days) == "2026-10-12" and max(days) == "2026-11-29"
    assert [w["label"] for w in cal["weeks"]][:2] == ["1주차", "2주차"] and "".join(cal["weekdays"]) == "월화수목금토일"
    assert cal["weeks"][6]["cells"][0]["date"] == "2026-11-23" and cal["weeks"][3]["cells"][0]["date"] == "2026-11-02"
    assert not days["2026-11-24"]["in_period"] and days["2026-11-23"]["in_period"]
    assert cal["now_week"] == "6주차" and cal["weeks"][5]["now"]
    # typed 는 11-20 에 결과 5건·실행 5번 — 진단한 날이 하루뿐이면 그날이 가장 진하다
    assert days["2026-11-20"]["runs"] == 5 and days["2026-11-20"]["level"] >= 1 and days["2026-11-20"]["today"]
    assert days["2026-11-23"]["kind"] == "final" and days["2026-11-02"]["kind"] == "mid"
    assert days["2026-11-18"]["mark"] == ""  # 주간보고는 달력에 넣지 않는다(11-20)
    assert days["2026-11-21"]["future"] and not days["2026-11-19"]["future"]
    assert cal["next"] == {"label": "최종보고회", "md": "11-23", "days": 3}


def test_work_levels_follow_rank_not_the_busiest_day():
    """퍼징 하루가 너무 많아도 다른 날이 다 옅어지지 않게 순위로 네 단계를 나눈다."""
    lv = stats._levels({"a": 0, "b": 1, "c": 2, "d": 3, "e": 500})
    assert lv["a"] == 0 and lv["b"] < lv["c"] < lv["d"] <= lv["e"] == 4
    assert stats._work(runs=2, requests=300, found=1) == 6


def test_sesacedu_pack_has_the_project_period(app):
    from dashboard import routes
    with app.test_request_context():
        sched = routes._projects()["sesacedu"].schedule
    assert sched["start"] == "2026-10-12" and sched["end"] == "2026-11-23" and sched["weeks"] == 7
    assert [m["label"] for m in sched["marks"]] == ["중간보고", "최종보고회"] and "weekly" not in sched
