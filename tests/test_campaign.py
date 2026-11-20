"""수사보드 캠페인 — 관찰한 버전 → CVE 후보, 팀이 고른 노드·선 저장."""
import json

from dashboard import cve
from dashboard.db import get_db


def _target(app, url="https://sesacedu.store", project="sesacedu", role="user_web"):
    with app.app_context():
        db = get_db()
        cur = db.execute("INSERT INTO targets (project, role, name, url, created_at) VALUES (?, ?, 't', ?, 'now')",
                         [project, role, url])
        db.commit()
        return cur.lastrowid


def _finding(app, tid, evidence, title="오류 페이지에 서버 버전 노출"):
    with app.app_context():
        db = get_db()
        run = db.execute("INSERT INTO runs (target_id, module_id, status, started_at) VALUES (?, 'tech_fingerprint', 'done', 'now')",
                         [tid]).lastrowid
        fid = db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, technique, created_at) "
                         "VALUES (?, ?, 'tech_fingerprint', ?, 'low', 'https://sesacedu.store/x', ?, 'T1592.002', 'now')",
                         [run, tid, title, evidence]).lastrowid
        db.commit()
        return fid


# ── 관찰한 버전 ──────────────────────────────────────────

def test_observe_reads_banner_versions():
    rows = [{"id": 1, "title": "a", "location": "/", "evidence": "GET / → 404\n본문: …Apache Tomcat/10.1.1…"},
            {"id": 2, "title": "b", "location": "/", "evidence": "Server: nginx/1.24.0 (Ubuntu)"},
            {"id": 3, "title": "c", "location": "/", "evidence": "Server: Werkzeug/3.1.9 Python/3.13.15"},
            {"id": 4, "title": "d", "location": "/", "evidence": "또 Apache Tomcat/10.1.1"}]
    got = {(o["product"], o["version"]): o for o in cve.observe(rows)}
    assert set(got) == {("Apache Tomcat", "10.1.1"), ("nginx", "1.24.0"), ("Werkzeug", "3.1.9"), ("Python", "3.13.15")}
    assert got[("Apache Tomcat", "10.1.1")]["finding_id"] == 1      # 같은 버전은 처음 본 결과 하나로
    assert got[("nginx", "1.24.0")]["distro"] == "Ubuntu"            # 배포판 패키지 — 백포팅 경고용


def test_observe_ignores_versionless_names():
    assert cve.observe([{"id": 1, "title": "", "location": "", "evidence": "Server: Apache-Coyote/1.1"}]) == []


# ── 팀 목록과 NVD 를 섞지 않는다 ─────────────────────────────

def test_team_list_follows_target_role():
    user_web = {"project": "sesacedu", "role": "user_web"}
    admin = {"project": "sesacedu", "role": "admin_web"}

    class Row(dict):
        def keys(self):
            return super().keys()
    ids_user = {c["id"] for c in cve.team_list(Row(user_web))}
    names_admin = {c["name"] for c in cve.team_list(Row(admin))}
    assert "CVE-2021-44228" in ids_user and "CVE-2025-24813" in ids_user
    assert any("React2Shell" in n for n in names_admin)
    assert cve.team_list(Row({"project": "general", "role": ""})) == []


def test_nvd_rows_stay_guess_unless_team_says_otherwise(app):
    tid = _target(app)
    _finding(app, tid, "본문: …Apache Tomcat/10.1.1…")
    fake = [{"id": "CVE-2025-24813", "score": 9.8, "severity": "critical", "vector": "", "kev": True,
             "published": "2025-03-10", "summary": "partial PUT"},
            {"id": "CVE-2023-0001", "score": 5.0, "severity": "medium", "vector": "", "kev": False,
             "published": "2023-01-01", "summary": "other"}]
    with app.app_context():
        db = get_db()
        found = db.execute("SELECT * FROM findings WHERE target_id = ?", [tid]).fetchall()
        asked, failed = cve.refresh(db, cve.observe(found), fetch=lambda name: fake, pause=0)
        assert asked == 1 and not failed
        t = db.execute("SELECT * FROM targets WHERE id = ?", [tid]).fetchone()
        c = cve.candidates(db, t, found)
    o = c["observed"][0]
    by = {r["id"]: r for r in o["cves"]}
    assert by["CVE-2025-24813"]["status"] == "확인" and by["CVE-2025-24813"]["team"]
    assert by["CVE-2023-0001"]["status"] == "추정" and not by["CVE-2023-0001"]["team"]
    assert o["cves"][0]["id"] == "CVE-2025-24813"                    # 팀이 다룬 것이 맨 위
    tomcat = next(x for x in c["team"] if x["id"] == "CVE-2025-24813")
    assert tomcat["seen_now"]                                         # 밖에서 본 버전과 맞는다


def test_nvd_failure_is_reported_not_raised(app):
    tid = _target(app)
    _finding(app, tid, "Server: nginx/1.24.0 (Ubuntu)")

    def down(name):
        raise OSError("network unreachable")
    with app.app_context():
        db = get_db()
        found = db.execute("SELECT * FROM findings").fetchall()
        asked, failed = cve.refresh(db, cve.observe(found), fetch=down, pause=0)
    assert asked == 2 and len(failed) == 2                            # f5:nginx, nginx:nginx 둘 다 물었다


def test_nvd_button_uses_cache_and_page_shows_candidates(app, client):
    tid = _target(app)
    _finding(app, tid, "본문: …Apache Tomcat/10.1.1…")
    sent = []
    app.config["NVD_FETCH"] = lambda name: sent.append(name) or [
        {"id": "CVE-2024-50379", "score": 9.8, "severity": "critical", "vector": "", "kev": False,
         "published": "2024-12-17", "summary": "TOCTOU"}]
    app.config["NVD_PAUSE_S"] = 0
    html = client.get(f"/scenario?target={tid}").get_data(as_text=True)
    assert "NVD 에서 CVE 찾기" in html and "CVE-2024-50379" not in html   # 열기만 해서는 안 묻는다
    assert not sent
    r = client.post("/cve/nvd", data={"target_id": tid})
    assert r.status_code == 302 and sent == ["cpe:2.3:a:apache:tomcat:10.1.1"]
    html = client.get(f"/scenario?target={tid}").get_data(as_text=True)
    assert "CVE-2024-50379" in html and "추정" in html


def test_parse_nvd_response():
    item = {"cve": {"id": "CVE-2023-44487", "published": "2023-10-10T14:15:10.883",
                    "cisaExploitAdd": "2023-10-10",
                    "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "HTTP/2 rapid reset"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH",
                                                                 "vectorString": "CVSS:3.1/AV:N"}}]}}}
    got = cve._slim(item)
    assert got == {"id": "CVE-2023-44487", "score": 7.5, "severity": "high", "vector": "CVSS:3.1/AV:N",
                   "kev": True, "published": "2023-10-10", "summary": "HTTP/2 rapid reset"}


# ── 캠페인 ─────────────────────────────────────────────

def _make_campaign(client, tid, name="S1 웹에서 관리자까지"):
    r = client.post("/campaigns", data={"target_id": tid, "name": name, "goal": "관리자 권한"})
    assert r.status_code == 302 and "campaign=" in r.headers["Location"]
    return int(r.headers["Location"].split("campaign=")[1].split("#")[0].split("&")[0])


def test_campaign_nodes_and_edges(app, client):
    tid = _target(app)
    fid = _finding(app, tid, "본문: …Apache Tomcat/10.1.1…")
    cid = _make_campaign(client, tid)

    s = client.post(f"/campaigns/{cid}/nodes", data={"kind": "observed", "ref": "Apache Tomcat 10.1.1",
                                                      "tactic": "TA0043", "title": "Apache Tomcat 10.1.1",
                                                      "status": "확인"}).get_json()
    s = client.post(f"/campaigns/{cid}/nodes", data={"kind": "cve", "ref": "CVE-2025-24813", "tactic": "TA0001",
                                                      "title": "CVE-2025-24813", "status": "추정"}).get_json()
    s = client.post(f"/campaigns/{cid}/nodes", data={"kind": "manual", "tactic": "TA0002", "title": "JSP 웹셸 실행",
                                                      "status": "미확인", "note": "08_모의해킹/…"}).get_json()
    s = client.post(f"/campaigns/{cid}/nodes", data={"kind": "finding", "ref": fid, "tactic": "TA0043",
                                                      "title": "오류 페이지에 서버 버전 노출"}).get_json()
    assert [n["kind"] for n in s["nodes"]] == ["observed", "cve", "manual", "finding"]
    assert s["tactics"] == ["TA0043", "TA0001", "TA0002"]             # 공격 순서대로
    a, b, c = (n["id"] for n in s["nodes"][:3])

    # 같은 후보를 같은 열에 또 놓아도 하나
    s = client.post(f"/campaigns/{cid}/nodes", data={"kind": "cve", "ref": "CVE-2025-24813", "tactic": "TA0001",
                                                      "title": "CVE-2025-24813"}).get_json()
    assert len(s["nodes"]) == 4

    s = client.post(f"/campaigns/{cid}/edges", data={"src": a, "dst": b, "label": "버전 10.1.1"}).get_json()
    s = client.post(f"/campaigns/{cid}/edges", data={"src": b, "dst": c, "label": ""}).get_json()
    assert [(e["src"], e["dst"], e["label"]) for e in s["edges"]] == [(a, b, "버전 10.1.1"), (b, c, "")]
    eid = s["edges"][1]["id"]
    s = client.post(f"/campaigns/{cid}/edges/{eid}", data={"label": "JSP 조각 업로드"}).get_json()
    assert s["edges"][1]["label"] == "JSP 조각 업로드"

    # 노드를 다른 열로 옮기고, 지우면 이어진 선도 같이 사라진다
    s = client.post(f"/campaigns/{cid}/nodes/{c}", data={"tactic": "TA0003"}).get_json()
    assert next(n for n in s["nodes"] if n["id"] == c)["tactic"] == "TA0003"
    s = client.post(f"/campaigns/{cid}/nodes/{b}/delete").get_json()
    assert len(s["nodes"]) == 3 and s["edges"] == []

    html = client.get(f"/scenario?target={tid}&campaign={cid}").get_data(as_text=True)
    assert "S1 웹에서 관리자까지" in html
    raw = html.split('id="cp-state">', 1)[1].split("</script>", 1)[0]
    assert "JSP 웹셸 실행" in [n["title"] for n in json.loads(raw)["nodes"]]   # 보드는 이 상태로 그린다


def test_campaign_rejects_bad_values(app, client):
    tid = _target(app)
    cid = _make_campaign(client, tid)
    r = client.post(f"/campaigns/{cid}/nodes", data={"kind": "cve", "tactic": "TA9999", "title": "x"})
    assert r.status_code == 400 and "전술" in r.get_json()["error"]
    r = client.post(f"/campaigns/{cid}/nodes", data={"kind": "manual", "tactic": "TA0002", "title": "x", "status": "완료"})
    assert r.status_code == 400                                       # 상태는 지침의 4단계만
    n = client.post(f"/campaigns/{cid}/nodes", data={"kind": "manual", "tactic": "TA0002", "title": "x"}).get_json()["nodes"][0]
    r = client.post(f"/campaigns/{cid}/edges", data={"src": n["id"], "dst": n["id"]})
    assert r.status_code == 400                                       # 자기 자신은 잇지 않는다

    # 다른 캠페인의 노드와는 이을 수 없다
    other = _make_campaign(client, tid, "S2")
    m = client.post(f"/campaigns/{other}/nodes", data={"kind": "manual", "tactic": "TA0002", "title": "y"}).get_json()["nodes"][0]
    assert client.post(f"/campaigns/{cid}/edges", data={"src": n["id"], "dst": m["id"]}).status_code == 404
    assert client.post("/campaigns/9999/nodes", data={}).status_code == 404


def test_campaign_delete_and_empty_name(app, client):
    tid = _target(app)
    r = client.post("/campaigns", data={"target_id": tid, "name": "  "})
    assert r.status_code == 302
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM campaigns").fetchone()[0] == 0
    cid = _make_campaign(client, tid)
    client.post(f"/campaigns/{cid}/nodes", data={"kind": "manual", "tactic": "TA0002", "title": "x"})
    client.post(f"/campaigns/{cid}/delete")
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM campaign_nodes").fetchone()[0] == 0


def test_board_without_campaign_invites_one(app, client):
    tid = _target(app)
    html = client.get(f"/scenario?target={tid}").get_data(as_text=True)
    assert "캠페인을 만들면" in html and "새 캠페인" in html
