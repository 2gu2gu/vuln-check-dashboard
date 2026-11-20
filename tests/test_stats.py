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


def test_bars_are_scaled_to_the_biggest_target(app, two_targets):
    a, b = two_targets
    with app.app_context():
        db = get_db()
        rows = {r["target"]["id"]: r for r in stats.by_target(db, db.execute("SELECT * FROM targets").fetchall())}
    assert rows[a]["total"] == 5 and rows[a]["width"] == 100
    assert rows[b]["total"] == 1 and rows[b]["width"] == 20
    assert [g["severity"] for g in rows[a]["segments"]] == ["critical", "high", "low"]


def test_progress_counts_every_status(app, two_targets):
    a, _ = two_targets
    with app.app_context():
        pg = stats.progress(get_db(), a)
    n = {g["status"]: g["n"] for g in pg["segments"]}
    assert n == {"open": 4, "confirmed": 1, "fixed": 1, "false_positive": 0}
    assert pg["reviewed_pct"] == round(2 * 100 / 6, 1)


def test_results_page_draws_the_charts(client, two_targets):
    a, b = two_targets
    page = client.get(f"/?target={a}").get_data(as_text=True)
    assert 'class="kpis"' in page and "대상별 미조치" in page and "처리 진행" in page
    # 막대 조각은 아래 표를 거르는 링크다
    assert f'href="/?target={b}&amp;severity=medium"' in page
    # '확인됨' 도 아직 조치 전이라 미조치에 든다 — High 열린 것 2 + 확인됨 1
    assert 'data-tip="사용자 웹 · High 3건 (60.0%)"' in page
    # 색만으로 구분하지 않는다 — 표로 보기가 있다
    assert "표로 보기" in page
