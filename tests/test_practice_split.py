"""연습용 대상은 점검 대상 두 개와 같은 자리에 있으면 안 된다(11-05 지적).

연습용은 우리가 띄운 가짜 서버다. 고를 때·볼 때·내보낼 때 실제 점검 대상과
섞이면, 발표 자리에서 "이것도 점검한 건가요" 에 답을 못 한다.
"""
import json

import pytest

from dashboard.registry import PRACTICE_LABEL, group_targets

REAL = {"project": "sesacedu", "role": "user_web", "name": "사용자 웹",
        "url": "https://sesacedu.store"}
ADMIN = {"project": "sesacedu", "role": "admin_web", "name": "관리자 웹",
         "url": "https://admin.sesacedu.store"}
FAKE = {"project": "sesacedu", "role": "practice", "name": "연습",
        "url": "http://127.0.0.1:5051"}


def add(client, t):
    return client.post("/targets", data=t, follow_redirects=True)


def tid_of(app, url):
    from dashboard.db import get_db
    with app.app_context():
        row = get_db().execute("SELECT id FROM targets WHERE url = ?", [url]).fetchone()
    return row["id"] if row else None


# ── 팩이 연습용을 연습용이라고 말하는가 ────────────────────────

def test_the_pack_marks_the_practice_role(app):
    pj = app.config["PROJECTS"]["sesacedu"]
    assert pj.is_practice("practice") is True
    assert pj.is_practice("user_web") is False and pj.is_practice("admin_web") is False
    assert pj.is_practice("") is False and pj.is_practice("없는역할") is False


def test_a_role_that_ships_a_fake_account_must_be_marked_practice(app):
    """가짜 계정을 화면에 띄우는 역할은 실서버일 리가 없다 — 표시를 빠뜨리면 여기서 걸린다."""
    for pj in app.config["PROJECTS"].values():
        for role in (pj.login.get("demo_accounts") or {}):
            assert pj.is_practice(role), f"{pj.id}.{role} 에 practice 표시가 없습니다"


# ── 묶음 ───────────────────────────────────────────────────────

def test_practice_goes_into_its_own_group_at_the_end(app):
    groups = group_targets([FAKE, REAL, ADMIN], app.config["PROJECTS"])
    assert len(groups) == 2
    assert groups[0]["practice"] is False and groups[1]["practice"] is True
    assert [t["name"] for t in groups[0]["targets"]] == ["사용자 웹", "관리자 웹"]
    assert [t["name"] for t in groups[1]["targets"]] == ["연습"]


def test_the_practice_group_is_not_named_after_the_project(app):
    """같은 이름 아래 있으면 떼어 놓은 뜻이 없다."""
    groups = group_targets([FAKE], app.config["PROJECTS"])
    assert groups[0]["label"] == PRACTICE_LABEL
    assert "새싹에듀" not in groups[0]["label"] and "점검 대상 아님" in groups[0]["label"]


def test_a_target_whose_pack_is_gone_still_groups(app):
    groups = group_targets([{"project": "없어진것", "role": "x", "name": "옛 대상"}],
                           app.config["PROJECTS"])
    assert groups[0]["practice"] is False and "팩 없음" in groups[0]["label"]


# ── 화면 ───────────────────────────────────────────────────────

def test_the_dropdown_puts_them_in_separate_groups(app, client):
    add(client, REAL)
    add(client, FAKE)
    page = client.get("/targets").get_data(as_text=True)
    picker = page.split('id="target"', 1)[-1].split("</select>", 1)[0]
    assert f'<optgroup label="{PRACTICE_LABEL}">' in picker
    assert '<optgroup label="새싹에듀 모의해킹">' in picker
    # 연습용 줄은 프로젝트 묶음이 아니라 연습용 묶음 뒤에 있다
    assert picker.index("새싹에듀 모의해킹") < picker.index(PRACTICE_LABEL)
    assert picker.index("https://sesacedu.store") < picker.index("127.0.0.1:5051")


def test_the_badge_does_not_call_the_fake_server_the_project(app, client):
    add(client, FAKE)
    tid = tid_of(app, FAKE["url"])
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    top = page.split('class="top"', 1)[-1].split("</header>", 1)[0]
    assert "연습용 — 점검 대상 아님" in top
    assert 'class="proj-badge">새싹에듀 모의해킹' not in top


def test_a_real_target_still_shows_the_project_badge(app, client):
    add(client, REAL)
    tid = tid_of(app, REAL["url"])
    top = client.get(f"/targets?target={tid}").get_data(as_text=True)
    top = top.split('class="top"', 1)[-1].split("</header>", 1)[0]
    assert 'class="proj-badge">새싹에듀 모의해킹' in top
    assert "점검 대상 아님" not in top


# ── 기본 대상 ──────────────────────────────────────────────────

def test_the_default_target_is_never_the_practice_server(app, client):
    """연습용을 먼저 등록해도, 그냥 열었을 때 가짜 서버를 보고 있으면 안 된다."""
    add(client, FAKE)
    add(client, REAL)
    picker = client.get("/").get_data(as_text=True).split('id="target"', 1)[-1].split("</select>", 1)[0]
    chosen = [ln for ln in picker.splitlines() if "selected" in ln]
    assert len(chosen) == 1 and "https://sesacedu.store" in chosen[0]


def test_with_only_a_practice_target_it_is_still_usable(app, client):
    """실서버가 없으면 연습용이라도 골라져야 한다 — 빈 화면이 되면 안 된다."""
    add(client, FAKE)
    assert client.get("/").status_code == 200


# ── 내보내기 ───────────────────────────────────────────────────

def test_the_practice_report_does_not_read_like_an_engagement_result(app, client):
    add(client, FAKE)
    tid = tid_of(app, FAKE["url"])
    md = client.get(f"/report/{tid}.md").get_data(as_text=True)
    assert md.startswith("# 연습 기록")
    assert "# 점검 결과" not in md
    assert "점검 결과가 아닙니다" in md and "보고서에 넣지 마세요" in md


def test_the_real_report_is_unchanged(app, client):
    add(client, REAL)
    tid = tid_of(app, REAL["url"])
    md = client.get(f"/report/{tid}.md").get_data(as_text=True)
    assert md.startswith("# 점검 결과 — 사용자 웹")
    assert "연습" not in md.split("\n| # |")[0]


@pytest.mark.parametrize("target, practice", [(FAKE, True), (REAL, False)])
def test_the_json_says_so_without_reading_korean(app, client, target, practice):
    """받는 쪽이 한국어 이름을 부분일치로 뒤지지 않게 — 원시 id 와 참/거짓으로 준다."""
    add(client, target)
    tid = tid_of(app, target["url"])
    data = json.loads(client.get(f"/report/{tid}.json").get_data(as_text=True))
    assert data["practice"] is practice and data["target"]["practice"] is practice
    assert data["target"]["project_id"] == "sesacedu"
    assert data["target"]["role_id"] == target["role"]


# ── 모듈은 그대로 돌아야 한다 ──────────────────────────────────

def test_the_pack_modules_still_work_on_the_practice_server(app, client):
    """떼어 놓은 것은 화면과 내보내기뿐이다. 연습용에서 시험할 수 없으면 뜻이 없다."""
    add(client, FAKE)
    tid = tid_of(app, FAKE["url"])
    page = client.get(f"/tools?target={tid}&tool=sesacedu_material_traversal_fuzz").get_data(as_text=True)
    assert 'name="module_id" value="sesacedu_material_traversal_fuzz"' in page
    with app.app_context():
        from dashboard.registry import modules_for
        avail = modules_for(app.config["MODULES"], "sesacedu", "practice")
    for mid in ("sesacedu_exposed_paths", "sesacedu_lecture_sqli",
                "sesacedu_material_traversal", "sesacedu_material_traversal_fuzz"):
        assert mid in avail, f"{mid} 가 연습용에서 사라졌습니다"
