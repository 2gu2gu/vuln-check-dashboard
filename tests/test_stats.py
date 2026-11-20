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
