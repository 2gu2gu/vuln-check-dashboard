"""수사보드 — 확인된 것과 제안을 섞지 않는다."""
import pytest

from dashboard import board
from dashboard.db import get_db
from dashboard.registry import ModuleInfo


def mod(mid, tactic="TA0043", stage="check", vuln="기타", needs=()):
    m = ModuleInfo(id=mid, name=mid, category="분야", kind="passive",
                   attack=[{"tactic": tactic, "technique": "T1", "name": ""}],
                   description="", run=None, stage=stage, vuln=vuln)
    m._needs = list(needs)
    return m


def finding(module_id, technique="T1", severity="medium", title="찾음"):
    return {"module_id": module_id, "technique": technique, "severity": severity,
            "title": title, "location": "/x", "cvss_vector": ""}


TECH = {"T1": "TA0043", "T9": "TA0001"}


def rows(findings, modules, needs=None):
    return board.build(findings, modules, TECH, needs or (lambda m: getattr(m, "_needs", [])))


def add_target(client, url="https://sesacedu.store"):
    return client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹", "url": url},
                       follow_redirects=True)


# ── 섞지 않는다 ────────────────────────────────────────────────

def test_found_and_suggested_are_separate():
    r = rows([finding("a")], [mod("a"), mod("b")])
    col = next(x for x in r if x["tactic"] == "TA0043")
    assert [f["module_id"] for f in col["found"]] == ["a"]
    assert [s["mod"].id for s in col["suggest"]] == ["b"]


def test_a_module_that_already_found_something_is_not_suggested_again():
    """남겨 두면 '한 번 더 돌려라' 로 읽힌다."""
    col = next(x for x in rows([finding("a")], [mod("a")]) if x["tactic"] == "TA0043")
    assert col["suggest"] == [] and col["done"] is True


def test_the_same_module_can_still_be_suggested_in_another_tactic():
    """정찰에서 결과를 냈다고 초기 접근에서도 빼면 안 된다 — 거기선 아직 안 돌렸다."""
    m = ModuleInfo(id="a", name="a", category="c", kind="passive", run=None, description="",
                   attack=[{"tactic": "TA0043", "technique": "T1"}, {"tactic": "TA0001", "technique": "T9"}])
    r = rows([finding("a", "T1")], [m])
    recon = next(x for x in r if x["tactic"] == "TA0043")
    access = next(x for x in r if x["tactic"] == "TA0001")
    assert recon["suggest"] == [] and [s["mod"].id for s in access["suggest"]] == ["a"]


# ── 왜 못 돌리는지 ─────────────────────────────────────────────

def test_a_blocked_module_says_what_is_missing():
    need = {"kind": "auth_header", "name": "Authorization", "label": "인증 헤더",
            "required": True, "ready": False, "why": "", "how": ""}
    s = rows([], [mod("a", needs=[need])])[0]["suggest"][0]
    assert s["state"] == board.BLOCKED and "인증 헤더 Authorization" in s["why"]


def test_an_unknowable_need_does_not_block():
    """칼리에서 돌렸는지 대시보드는 알 수 없다 — 모른다고 막으면 안 된다."""
    need = {"kind": "tool", "name": "fsmap", "label": "바깥 도구",
            "required": True, "ready": None, "why": "", "how": ""}
    assert rows([], [mod("a", needs=[need])])[0]["suggest"][0]["state"] == board.READY


@pytest.mark.parametrize("stage, word", [("probe", "표면 탭"), ("tool", "도구 탭")])
def test_modules_that_run_elsewhere_say_where(stage, word):
    s = rows([], [mod("a", stage=stage)])[0]["suggest"][0]
    assert s["state"] == board.ELSEWHERE and word in s["why"]


# ── 빈 칸 ─────────────────────────────────────────────────────

def test_a_tactic_with_nothing_at_all_is_left_out():
    """빈 칸만 늘어서면 흐름이 안 보인다."""
    assert [r["tactic"] for r in rows([], [mod("a")])] == ["TA0043"]


def test_order_follows_the_attack_kill_chain():
    r = rows([], [mod("a", tactic="TA0002"), mod("b", tactic="TA0043")])
    assert [x["name"] for x in r] == ["정찰", "실행"]


# ── 한 줄 요약 ─────────────────────────────────────────────────

def test_summary_points_at_the_next_thing_that_can_actually_run():
    need = {"kind": "auth_header", "name": "A", "label": "인증 헤더",
            "required": True, "ready": False, "why": "", "how": ""}
    r = rows([finding("a")], [mod("a"), mod("blocked", tactic="TA0001", needs=[need]),
                              mod("ok", tactic="TA0002")])
    s = board.summary(r)
    assert s["done"] == 1 and s["last"] == "정찰"
    assert s["next"] == "실행" and s["next_mods"] == ["ok"]   # 막힌 '초기 접근' 은 건너뛴다
    assert s["blocked"] == 1


def test_summary_with_nothing_done():
    s = board.summary(rows([], [mod("a")]))
    assert s["done"] == 0 and s["last"] == "" and s["next"] == "정찰"


# ── 화면 ──────────────────────────────────────────────────────

def test_board_page(app, client, monkeypatch, fake_fetch):
    from modules import http_security_headers
    monkeypatch.setattr(http_security_headers, "fetch", fake_fetch({"/": {}}))
    add_target(client)
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"})
    html = client.get(f"/scenario?target={tid}").get_data(as_text=True)
    assert "수사보드" in html
    assert "확인됨" in html and "제안" in html
    assert "bd-card done" in html and "bd-card todo" in html
    assert "기법 사이의 연결은 쓰지 않습니다" in html or "쓰지 않습니다" in html


def test_board_without_a_target_asks_for_one(client):
    assert "대상을 먼저" in client.get("/scenario").get_data(as_text=True)
