"""모듈을 어떤 기준으로 묶어 보여 줄지 — 탭·왼쪽 드로어."""
import pytest

from dashboard import grouping
from dashboard.registry import ModuleInfo


def mod(mid, stage="check", category="설정 점검", vuln="기타", tactics=("TA0043",), project=""):
    return ModuleInfo(id=mid, name=mid, category=category, kind="passive",
                      attack=[{"tactic": t, "technique": "T1"} for t in tactics],
                      description="", run=None, stage=stage, vuln=vuln, project=project)


def add_target(client, url="https://sesacedu.store"):
    return client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹", "url": url},
                       follow_redirects=True)


# ── 묶기 ──────────────────────────────────────────────────────

def test_default_is_stage_in_the_order_people_use_it():
    """단계가 기본인 이유는 그게 쓰는 순서라서다 — 표면 모으고 → 찔러 보고 → 보고."""
    rows = grouping.group([mod("a", stage="tool"), mod("b", stage="collect"), mod("c", stage="probe")])
    assert [r["label"] for r in rows] == ["표면 수집", "지점 점검", "도구"]


def test_unknown_way_falls_back_to_stage():
    assert grouping.group([mod("a")], "없는기준") == grouping.group([mod("a")], "stage")


def test_a_module_with_two_tactics_shows_in_both():
    """숨기면 '그 전술에는 쓸 모듈이 없다' 로 읽힌다 — 그건 사실이 아니다."""
    rows = grouping.group([mod("a", tactics=("TA0043", "TA0001"))], "tactic")
    assert [r["label"] for r in rows] == ["정찰", "초기 접근"]
    assert all(len(r["modules"]) == 1 for r in rows)


def test_tactics_come_in_attack_order():
    rows = grouping.group([mod("a", tactics=("TA0002",)), mod("b", tactics=("TA0043",))], "tactic")
    assert [r["label"] for r in rows] == ["정찰", "실행"]


def test_module_with_no_tactic_is_not_dropped():
    rows = grouping.group([mod("a", tactics=())], "tactic")
    assert [r["label"] for r in rows] == ["전술 없음"]


def test_vuln_uses_the_notion_vocabulary_in_its_order():
    rows = grouping.group([mod("a", vuln="SQL"), mod("b", vuln="정보노출"), mod("c")], "vuln")
    assert [r["label"] for r in rows] == ["정보노출", "SQL", "기타"]


def test_vuln_says_which_types_have_no_module_yet():
    """'XSS 칸이 비었다' 는 '아직 XSS 모듈이 없다' 는 뜻이고, 다음에 만들 것을 고르는 데 쓴다."""
    rows = grouping.group([mod("a", vuln="SQL")], "vuln")
    assert set(grouping.empty_groups("vuln", rows)) == {"정보노출", "AUTH", "XSS", "FILE"}
    assert grouping.empty_groups("stage", rows) == []        # 다른 기준에는 '없는 묶음' 개념이 없다


def test_category_groups_biggest_first():
    rows = grouping.group([mod("a", category="가"), mod("b", category="나"), mod("c", category="나")], "category")
    assert [r["label"] for r in rows] == ["나", "가"]


# ── META 어휘 검사 ─────────────────────────────────────────────

def test_a_made_up_vuln_word_stops_the_module_loading():
    """어휘가 갈라지면 노션 취약점 항목과 안 묶인다."""
    from dashboard.registry import _check_vuln
    assert _check_vuln("") == "기타"
    assert _check_vuln("SQL") == "SQL"
    with pytest.raises(ValueError, match="vuln"):
        _check_vuln("SQLi")


def test_shipped_modules_use_the_vocabulary(app):
    with app.app_context():
        for m in app.config["MODULES"].values():
            assert m.vuln in grouping.VULN_TYPES, m.id


# ── 화면 ──────────────────────────────────────────────────────

@pytest.mark.parametrize("way, want", [
    ("stage", "단계"), ("tactic", "전술"), ("category", "분야"), ("vuln", "취약점"),
])
def test_tab_is_marked_on(client, way, want):
    html = client.get(f"/modules?by={way}").get_data(as_text=True)
    assert f'class="by-tab on" role="tab" aria-selected="true"' in html
    assert f">{want}</a>" in html


def test_page_defaults_to_stage(client):
    html = client.get("/modules").get_data(as_text=True)
    assert "표면 수집" in html and 'aria-selected="true"' in html


def test_left_drawer_lists_the_groups(app, client):
    add_target(client)
    html = client.get("/modules?by=category").get_data(as_text=True)
    assert 'id="mod-drawer"' in html and 'href="#g-1"' in html


def test_vuln_page_shows_what_is_missing(client):
    html = client.get("/modules?by=vuln").get_data(as_text=True)
    assert "아직 없는 유형" in html or "기타" in html
