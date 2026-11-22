"""Word 보고서 — 짜임과 그림(11-22).

팀 보고서 생성 도구(`SaeMoi/auto_report`)와 팀이 실제로 낸 최종 결과보고서를 기준으로 본다.
거기 4-1 은 지표 칸 넷 · 총평 한 문단 · 그림 둘이고, 4-2 는 대상마다 한 줄에 구역 소계와
합계가 붙는다. 그림은 그림 파일이 아니라 Word 차트 부품이어야 한다 — 서버에 한글 글꼴이
없어서 그림 파일로 만들면 축 이름이 네모로 나온다.
"""
import io
import re
import zipfile

import pytest
from docx import Document

from dashboard import report_board, report_chart
from dashboard.db import get_db
from tests.test_app import add_target, target_id

CHART_PART = re.compile(r"word/charts/chart\d+\.xml")


# ── 밑감 ──────────────────────────────────────────────────────

def _finding(db, tid, module, severity, title="문제", status="open"):
    run = db.execute("INSERT INTO runs (target_id, module_id, started_at, status) "
                     "VALUES (?, ?, '2026-11-22', 'done')", [tid, module]).lastrowid
    db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, status, "
               "location, evidence, recommendation, created_at) "
               "VALUES (?, ?, ?, ?, ?, ?, 'https://sesacedu.store/x', '근거', '고치는 법', '2026-11-22')",
               [run, tid, module, title, severity, status])


@pytest.fixture
def two_webs(app, client):
    """사용자 웹(A-01)·관리자 웹(A-02) 둘에 결과를 깔아 둔다."""
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    add_target(client, "https://admin.sesacedu.store", name="관리자 웹", role="admin_web")
    a, b = target_id(app, "https://sesacedu.store"), target_id(app, "https://admin.sesacedu.store")
    with app.app_context():
        db = get_db()
        _finding(db, a, "sesacedu_lecture_sqli", "critical", "검색어에 SQL 주입")
        _finding(db, a, "http_security_headers", "low", "CSP 헤더 없음")
        _finding(db, a, "http_security_headers", "low", "HSTS 헤더 없음")
        _finding(db, b, "port_check", "medium", "예상 밖 포트")
        _finding(db, b, "http_security_headers", "low", "CSP 헤더 없음")
        _finding(db, a, "tech_fingerprint", "info", "서버 정보", status="false_positive")
        db.commit()
    return a, b


def _docx(client, tid):
    res = client.get(f"/report/{tid}.docx")
    assert res.status_code == 200
    return res.get_data()


def _text(blob):
    doc = Document(io.BytesIO(blob))
    out = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        out += [c.text for row in t.rows for c in row.cells]
    return "\n".join(out)


def _charts(blob):
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        return {n: z.read(n).decode("utf-8") for n in z.namelist() if CHART_PART.fullmatch(n)}


# ── 한 파일에 대상이 다 담기는가 ───────────────────────────────

def test_one_file_covers_every_real_target_of_the_project(client, two_webs):
    """전에는 대상 하나였다 — 그러면 4장 그림이 막대 한 줄짜리가 된다(11-22)."""
    text = _text(_docx(client, two_webs[0]))
    assert "A-01 사용자 웹" in text and "A-02 관리자 웹" in text
    assert "5-2. [외부(DMZ)] 구역 — A-01 사용자 웹" in text
    assert "5-3. [관리·내부] 구역 — A-02 관리자 웹" in text
    # 어느 대상에서 뽑든 같은 문서다
    assert _text(_docx(client, two_webs[1])).count("5-3.") == text.count("5-3.")


def test_practice_target_is_reported_on_its_own(app, client):
    """연습용 기록이 점검 결과에 섞이면 안 된다."""
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    add_target(client, "http://127.0.0.1:5051", name="연습용 대상", role="practice")
    real = target_id(app, "https://sesacedu.store")
    fake = target_id(app, "http://127.0.0.1:5051")
    with app.app_context():
        db = get_db()
        _finding(db, real, "http_security_headers", "low")
        _finding(db, fake, "http_security_headers", "high", "연습에서 나온 것")
        db.commit()
    text = _text(_docx(client, fake))
    assert "연습용 가짜 서버" in text and "연습에서 나온 것" in text
    assert "사용자 웹" not in text
    assert "연습에서 나온 것" not in _text(_docx(client, real))


# ── 4-1 총평 ──────────────────────────────────────────────────

def test_4_1_has_the_four_metric_cards_and_one_overall_paragraph(client, two_webs):
    text = _text(_docx(client, two_webs[0]))
    assert "4-1. 총평" in text
    assert "취약점 · 건 (V-xx · V-xx-n)" in text and "취약점이 나온 대상" in text
    assert "3개 · 5건" in text                      # 오탐 1건은 빠진 수
    assert "2 / 2곳" in text
    assert "자동 점검에서 취약점 3개 · 5건이 나왔음." in text
    assert "Critical 1건, High 0건, Medium 1건, Low 3건, 참고 0건" in text
    # 센 것과 사람이 확인한 것을 섞지 않는다
    assert "5건은 아직 미확인임" in text
    # 공통 원인은 코드를 봐야 아는 것이라 비워 둔다
    assert "공통 원인" in text and "사람이 적습니다" in text


def test_the_overall_paragraph_names_what_to_look_at_first(client, two_webs):
    text = _text(_docx(client, two_webs[0]))
    assert "점수가 높은 순으로 먼저 볼 것은 V-01(강의 목록 SQL 주입 (심화))" in text


# ── 4-2 대상별 요약 ───────────────────────────────────────────

def test_4_2_adds_a_subtotal_per_zone_and_a_grand_total(client, two_webs):
    doc = Document(io.BytesIO(_docx(client, two_webs[0])))
    table = next(t for t in doc.tables if t.rows[0].cells[0].text == "구역")
    body = [[c.text for c in r.cells] for r in table.rows[1:]]
    assert [r[0] for r in body] == ["외부(DMZ)", "외부(DMZ) 소계", "관리·내부", "관리·내부 소계", "합계"]
    assert body[-1][-1] == "5"                      # 합계는 건 수와 같다
    assert body[1][-1] == "3" and body[3][-1] == "2"


def test_the_vulnerability_list_never_leaves_the_owasp_cell_broken(client, two_webs):
    """포트 확인처럼 KISA 21항목 밖 모듈도 유형이 붙는다(자체 항목 X-01 → A02)."""
    doc = Document(io.BytesIO(_docx(client, two_webs[0])))
    table = next(t for t in doc.tables if t.rows[0].cells[0].text == "V-ID"
                 and t.rows[0].cells[2].text.startswith("취약점 유형"))
    kinds = {r.cells[1].text: r.cells[2].text for r in table.rows[1:]}
    assert kinds["열린 포트 확인"] == "A02"
    assert kinds["강의 목록 SQL 주입 (심화)"] == "A05"
    assert "[" not in "".join(kinds.values())


def test_v_ids_are_numbered_once_for_the_whole_document(client, two_webs):
    """3-2·4-2·5장이 같은 번호를 써야 사람이 표와 상세를 이어 읽는다."""
    text = _text(_docx(client, two_webs[0]))
    assert "V-01. 강의 목록 SQL 주입 (심화)" in text
    ids = set(re.findall(r"V-\d\d(?=\.|\s|-)", text))
    assert ids == {"V-01", "V-02", "V-03"}          # 모듈 셋 — 오탐으로 내린 것은 빠진다


# ── 그림 ──────────────────────────────────────────────────────

def test_the_figures_are_word_charts_not_pictures(client, two_webs):
    """그림 파일로 만들면 서버에 한글 글꼴이 없어 축 이름이 네모로 나온다."""
    blob = _docx(client, two_webs[0])
    charts = _charts(blob)
    assert len(charts) == 3                          # 위험도별 · 대상별 · 유형별
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        rels = z.read("word/_rels/document.xml.rels").decode("utf-8")
        types = z.read("[Content_Types].xml").decode("utf-8")
    assert rels.count("relationships/chart") == 3
    assert types.count("drawingml.chart+xml") == 3


def test_the_severity_chart_carries_the_same_numbers_as_the_table(client, two_webs):
    charts = _charts(_docx(client, two_webs[0]))
    one = next(x for x in charts.values() if "위험도별 건수" in x)
    nums = re.findall(r"<c:pt idx=\"\d\"><c:v>(\d+)</c:v></c:pt>", one.split("<c:val>")[1])
    assert nums == ["1", "0", "1", "3", "0"]         # Critical·High·Medium·Low·Info


def test_charts_leave_out_rows_and_grades_that_have_nothing(client, two_webs):
    """0 만 있는 줄·등급을 그리면 빈 줄이 늘어서 그림을 못 읽는다."""
    charts = _charts(_docx(client, two_webs[0]))
    kinds = next(x for x in charts.values() if "취약점 유형별" in x)
    assert "A05 Injection" in kinds and "A02 Security Misconfiguration" in kinds
    assert "A03 Software Supply Chain Failures" not in kinds
    assert "High" not in kinds                       # High 0건 — 계열 자체를 안 만든다


def test_a_number_that_cannot_fit_its_segment_is_left_out():
    """1~2건짜리 구간에 숫자를 두면 옆 숫자와 겹치거나 잘린다(11-22 사용자 지적).

    서버 숫자(사용자 웹 174건)로 재 본다 — 전체가 작을 때는 1건도 넓어서 그대로 적는다.
    """
    big = report_chart.stacked(
        "대상별", ["A-01", "A-02"],
        [{"name": "Critical", "values": [6, 0], "color": "9C3E39"},
         {"name": "Medium", "values": [140, 46], "color": "A88B35"},
         {"name": "Info", "values": [4, 1], "color": "7B7F86"}])
    hid = {s["name"]: s["hide"] for s in big["series"]}
    assert hid["Medium"] == []                       # 140·46 은 넉넉하다
    assert hid["Info"] == [0, 1]                     # 4·1 은 숫자가 안 들어간다

    small = report_chart.stacked(
        "작은 것", ["A-01"],
        [{"name": "Critical", "values": [1], "color": "9C3E39"},
         {"name": "Low", "values": [3], "color": "5E7C5A"}])
    assert all(s["hide"] == [] for s in small["series"]), "전체가 작으면 1건도 넓다"


def test_a_horizontal_chart_puts_the_first_row_on_top(client, two_webs):
    """줄을 뒤집어 그리면 값축도 같이 뒤집혀 위로 간다 — 아래로 내려놔야 읽힌다."""
    charts = _charts(_docx(client, two_webs[0]))
    one = next(x for x in charts.values() if "대상별 위험도 분포" in x)
    assert '<c:orientation val="maxMin"/>' in one.split("<c:catAx>")[1]
    assert '<c:crosses val="max"/>' in one.split("<c:valAx>")[1]


# ── 차트 XML 자체 ─────────────────────────────────────────────

# ── 시나리오(수사보드 캠페인) ─────────────────────────────────

def _campaign(app, tid, name="S1 버전에서 CVE 까지"):
    """보드 한 판 — 읽어 낸 것 → CVE → 결과 → 목표."""
    with app.app_context():
        db = get_db()
        found = db.execute("SELECT id FROM findings WHERE target_id = ? ORDER BY id", [tid]).fetchall()
        cid = db.execute("INSERT INTO campaigns (target_id, name, goal, created_at) "
                         "VALUES (?, ?, '읽어 낸 버전에서 어디까지 가는지', '2026-11-22')",
                         [tid, name]).lastrowid

        def node(kind, tactic, title, ref="", status="확인", x=0, y=0):
            return db.execute(
                "INSERT INTO campaign_nodes (campaign_id, kind, ref, tactic, title, sub, status, "
                "note, x, y, created_at) VALUES (?, ?, ?, ?, ?, '', ?, '', ?, ?, '2026-11-22')",
                [cid, kind, ref, tactic, title, status, x, y]).lastrowid

        seen = node("observed", "TA0043", "Apache Tomcat 10.1.1", x=20)
        cve = node("cve", "TA0001", "CVE-2021-44228", ref="CVE-2021-44228", x=700)
        hit = node("finding", "TA0001", "검색어에 SQL 주입", ref=str(found[0]["id"]), x=1400)
        more = node("finding", "TA0007", "CSP 헤더 없음", ref=str(found[1]["id"]),
                    status="추정", x=2100)
        goal = node("goal", "TA0040", "서버 장악", x=2800)
        for a, b, label in ((seen, cve, "버전이 맞음"), (cve, hit, "같은 제품"),
                            (hit, goal, "이걸로 가능"), (more, goal, "이걸로 가능")):
            db.execute("INSERT INTO campaign_edges (campaign_id, src, dst, label) VALUES (?, ?, ?, ?)",
                       [cid, a, b, label])
        db.commit()
    return cid


def test_a_campaign_becomes_part_b_of_the_report(client, app, two_webs):
    """수사보드 캠페인 하나가 시나리오 한 절이 된다(양식 6장)."""
    _campaign(app, two_webs[0])
    text = _text(_docx(client, two_webs[0]))
    assert "6  Part B. 시나리오 모의해킹 결과" in text
    assert "6-1. 시나리오 요약 — S1. 버전에서 CVE 까지" in text
    assert "공격 경로 한 줄" in text and "정찰 → 초기 접근 → 탐색" in text
    assert "S1-STEP1" in text and "S1-STEP4" in text
    assert "4-3. 목표 달성 여부" in text and "O-1" in text and "서버 장악" in text


def test_the_scenario_column_is_filled_from_the_board(client, app, two_webs):
    """양식의 '시나리오 사용' 칸 — 4-2 는 시나리오 번호, 5장 건별은 단계 번호다."""
    _campaign(app, two_webs[0])
    doc = Document(io.BytesIO(_docx(client, two_webs[0])))
    kinds = next(t for t in doc.tables if t.rows[0].cells[0].text == "V-ID"
                 and "시나리오 사용" in [c.text for c in t.rows[0].cells])
    used = {r.cells[1].text: r.cells[6].text for r in kinds.rows[1:]}
    assert used["강의 목록 SQL 주입 (심화)"] == "S1"
    assert used["열린 포트 확인"] == "-"            # 보드에 안 올라간 취약점
    cases = next(t for t in doc.tables if t.rows[0].cells[0].text == "건 ID")
    steps = {r.cells[0].text: r.cells[5].text for r in cases.rows[1:]}
    assert any(v.startswith("S1-STEP") for v in steps.values())


def test_without_a_campaign_the_report_stays_as_it_was(client, two_webs):
    """캠페인이 없으면 6장도 4-3 도 서지 않는다 — 빈 장을 만들지 않는다."""
    text = _text(_docx(client, two_webs[0]))
    assert "6  Part B. 시나리오 모의해킹 결과" not in text
    assert "4-3. 목표 달성" not in text


def test_the_chain_picture_is_drawn_as_word_shapes(client, app, two_webs):
    """그림 6-1 은 그림 파일이 아니라 도형 묶음이다 — Word 에서 카드를 끌어 옮길 수 있다.

    선은 직각으로 꺾는 가는 줄이어야 한다(미감 명세) — 곡선은 지렁이처럼 보인다.
    """
    _campaign(app, two_webs[0])
    blob = _docx(client, two_webs[0])
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        body = z.read("word/document.xml").decode("utf-8")
        assert not [n for n in z.namelist() if n.startswith("word/media/")]
    assert "wordprocessingGroup" in body and "roundRect" in body
    # 선은 손으로 그린 베지에 하나 — Word 커넥터는 높이 차가 작으면 S 자로 꿈틀거린다
    assert "cubicBezTo" in body and "curvedConnector" not in body


def test_the_columns_run_left_to_right_in_attack_order(client, app, two_webs):
    """열 하나가 전술 하나이고 왼쪽에서 오른쪽으로 흐른다 — 보드와 같은 짜임."""
    _campaign(app, two_webs[0])
    with app.app_context():
        db = get_db()
        nodes = [dict(r) for r in db.execute("SELECT * FROM campaign_nodes ORDER BY id")]
        edges = [dict(r) for r in db.execute("SELECT * FROM campaign_edges ORDER BY id")]
    cols, cards, links, _h = report_board.lay_out(nodes, edges, lambda i: "")
    assert [t for t, _line in cols] == ["TA0043", "TA0001", "TA0007", "TA0040"]
    xs = [c["x"] for _t, line in cols for c in line]
    assert xs == sorted(xs), "왼쪽 열이 먼저 온다"
    assert links, "선이 그려진다"


def test_findings_with_the_same_title_are_folded_into_one_card():
    """민감 파일 노출 7건을 카드 7장으로 그리면 그림이 못 읽게 된다."""
    nodes = [{"id": i, "kind": "finding", "ref": str(i), "tactic": "TA0007", "x": i * 10, "y": 0,
              "title": f"민감 파일 노출: /etc/{i}.conf", "sub": "", "status": "확인"}
             for i in range(1, 8)]
    nodes.append({"id": 9, "kind": "goal", "ref": "", "tactic": "TA0040", "x": 0, "y": 0,
                  "title": "서버 장악", "sub": "", "status": "추정"})
    _rows, cards, _links, _h = report_board.lay_out(nodes, [], lambda i: f"V-01-{i}")
    folded = [c for c in cards if c["kind"] == "finding"]
    assert len(folded) == 1 and len(folded[0]["ids"]) == 7
    assert "7건" in folded[0]["title"] and folded[0]["sub"].startswith("V-01-1")


def test_chart_xml_is_well_formed_and_keeps_the_values():
    from xml.etree import ElementTree

    spec = report_chart.stacked("제목 & <꺾쇠>", ["ㄱ", "ㄴ"],
                                [{"name": "Critical", "values": [2, 0], "color": "9C3E39"},
                                 {"name": "Low", "values": [0, 5], "color": "5E7C5A"}])
    xml = report_chart.chart_xml(spec)
    root = ElementTree.fromstring(xml)
    assert root.tag.endswith("chartSpace")
    assert "제목 &amp; &lt;꺾쇠&gt;" in xml           # 제목에 꺾쇠가 들어가도 깨지지 않는다
    assert xml.count("<c:ser>") == 2
    assert '<c:grouping val="stacked"/>' in xml and '<c:overlap val="100"/>' in xml


def test_a_chart_without_any_row_is_simply_not_drawn(app, client):
    """결과가 하나도 없는 대상에서도 보고서는 나와야 한다."""
    add_target(client, "https://sesacedu.store", name="사용자 웹")
    blob = _docx(client, target_id(app, "https://sesacedu.store"))
    assert "4-1. 총평" in _text(blob)
    assert len(_charts(blob)) == 1                   # 위험도별 하나만 — 나머지는 그릴 것이 없다
