"""CVSS 3.1 기본 점수. 팀 노션 '웹 서비스 취약점 목록' 이 쓰는 형식 그대로."""
import json

import pytest

from dashboard import cvss
from dashboard.db import get_db


def add_target(client, url="https://sesacedu.store"):
    return client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹", "url": url},
                       follow_redirects=True)


# ── 계산 ──────────────────────────────────────────────────────
# 널리 알려진 벡터로 맞춘다. 첫 줄은 팀 노션에 실제로 적혀 있는 벡터다.

@pytest.mark.parametrize("vector, score, label", [
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),   # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),      # 반사형 XSS
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "High"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "None"),
])
def test_known_vectors(vector, score, label):
    r = cvss.rate(vector)
    assert r["score"] == score and r["label"] == label


def test_scope_changed_raises_the_score():
    """범위가 넘어가면 같은 영향이라도 점수가 높다."""
    same = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    over = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert cvss.rate(over)["score"] > cvss.rate(same)["score"]


def test_30_vectors_are_read_too():
    assert cvss.rate("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")["score"] == 6.5


@pytest.mark.parametrize("bad, why", [
    ("", "비어"),
    ("AV:N/AC:L", "CVSS:3"),
    ("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "빠진"),
    ("CVSS:3.1/ZZ:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "모르는"),
])
def test_bad_vectors_say_what_is_wrong(bad, why):
    with pytest.raises(cvss.BadVector, match=why):
        cvss.rate(bad)


def test_maps_onto_the_notion_three_grades():
    """노션의 CVSS 속성은 Low·Medium·High 세 가지뿐이다 — Critical 은 High 로 간다."""
    assert cvss.rate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["notion"] == "High"
    assert cvss.rate("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")["notion"] == "Medium"


def test_impact_text_matches_the_notion_cell():
    assert cvss.rate("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")["impact_text"] == "Medium(6.5)"


# ── 모듈이 적어 둔 제안 벡터 ────────────────────────────────────

def test_module_vectors_are_valid(app):
    with app.app_context():
        for mod in app.config["MODULES"].values():
            if mod.cvss:
                cvss.parse(mod.cvss)          # 틀리면 BadVector


# ── 화면과 저장 ────────────────────────────────────────────────

def test_score_endpoint(client):
    r = client.get("/cvss?AV=N&AC=L&PR=L&UI=N&S=U&C=H&I=N&A=N")
    assert r.status_code == 200 and r.get_json()["score"] == 6.5
    assert client.get("/cvss?AV=N").status_code == 400


def test_editor_is_on_the_results_page(app, client):
    add_target(client)
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"},
                follow_redirects=True)
    html = client.get(f"/?target={tid}").get_data(as_text=True)
    assert "영향도 (CVSS 3.1)" in html
    for key in cvss.ORDER:
        assert f'name="cvss_{key}"' in html


def test_saving_a_vector_sets_the_severity(app, client):
    """등급을 손으로 따로 적게 두면 벡터와 어긋난다 — 점수에서 다시 매긴다."""
    add_target(client)
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"},
                follow_redirects=True)
    with app.app_context():
        fid = get_db().execute("SELECT id FROM findings").fetchone()["id"]

    client.post(f"/findings/{fid}/status", data={
        "status": "confirmed", "cvss_AV": "N", "cvss_AC": "L", "cvss_PR": "N", "cvss_UI": "N",
        "cvss_S": "U", "cvss_C": "H", "cvss_I": "H", "cvss_A": "H"}, follow_redirects=True)
    with app.app_context():
        row = get_db().execute("SELECT cvss_vector, severity FROM findings WHERE id = ?", [fid]).fetchone()
    assert row["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert row["severity"] == "critical"          # 9.8 → Critical

    client.post(f"/findings/{fid}/status", data={"status": "confirmed", "cvss": "clear"},
                follow_redirects=True)
    with app.app_context():
        assert get_db().execute("SELECT cvss_vector FROM findings WHERE id = ?", [fid]).fetchone()[0] == ""


def test_report_follows_the_team_template(app, client):
    add_target(client)
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"},
                follow_redirects=True)
    with app.app_context():
        fid = get_db().execute("SELECT id FROM findings").fetchone()["id"]
    client.post(f"/findings/{fid}/status", data={
        "status": "confirmed", "cvss_AV": "N", "cvss_AC": "L", "cvss_PR": "L", "cvss_UI": "N",
        "cvss_S": "U", "cvss_C": "H", "cvss_I": "N", "cvss_A": "N"}, follow_redirects=True)

    md = client.get(f"/report/{tid}.md").get_data(as_text=True)
    for heading in ("### 1. 취약점 개요", "### 2. 취약점 상세설명", "### 3. 악용 시나리오", "### 4. 조치방안"):
        assert heading in md
    assert "| 영향도(CVSS 3.1) | Medium(6.5) |" in md
    assert "| CVSS Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |" in md

    data = json.loads(client.get(f"/report/{tid}.json").get_data(as_text=True))
    one = next(f for f in data["findings"] if f["cvss"])
    assert one["cvss"]["score"] == 6.5 and one["cvss"]["saved"] is True


def test_unrated_finding_says_so(app, client):
    add_target(client)
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    client.post("/modules/http_security_headers/run", data={"target_id": tid, "path": "/"},
                follow_redirects=True)
    md = client.get(f"/report/{tid}.md").get_data(as_text=True)
    # 보안 헤더 모듈은 제안 벡터가 없다 — 없는 것을 있는 척하지 않는다
    assert "**미평가**" in md
