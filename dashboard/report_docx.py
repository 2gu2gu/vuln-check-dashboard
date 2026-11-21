"""점검 결과를 Word(.docx) 로 낸다 — 내려받기 단추가 주는 것(11-21 사용자 지시).

왜 여기서 따로 만드나. 작업공간에는 공용 변환기(`md2docx` 스킬)가 있지만 그건 **내 컴퓨터의
CLI** 다. 대시보드는 EC2-4 에서 돌고 거기에는 Node 도 그 스킬도 없다. 그래서 서버에서 바로
만들 수 있는 python-docx 로 같은 뼈대를 쓴다. **마크다운을 거치지 않는다** — 한 번 글자로
바꿨다가 다시 읽으면 표 안의 `|` 같은 것이 깨진다.

문서 뼈대는 팀 노션 '웹 서비스 취약점 목록' 의 본문 양식 그대로다(1.개요 / 2.상세 /
3.시나리오 / 4.조치). 마크다운 보고서(`/report/<id>.md`)와 **같은 내용, 같은 순서**다.

제출용 Word 양식(`01_제출물/결과보고서_양식/`)에 맞추는 것은 아직이다. 지금은 내용을 담은
깨끗한 문서를 준다 — 양식에 얹는 것은 사람이 하거나, 양식 파일을 받아 다음에 맞춘다.
"""
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

MONO = "Consolas"
GREY = RGBColor(0x55, 0x55, 0x55)
# 코드 토막은 길어질 수 있다. 통째로 넣으면 표지 한 장이 코드로 덮인다 — 앞부분만 넣고 말해 준다
CODE_LINES = 60


def _mono(p, text, size=9):
    r = p.add_run(text)
    r.font.name = MONO
    r.font.size = Pt(size)
    return r


def _code(doc, text, head=""):
    """근거·요청·응답처럼 그대로 보여야 하는 토막."""
    if head:
        h = doc.add_paragraph()
        h.add_run(head).bold = True
    lines = (text or "").splitlines() or [""]
    cut = len(lines) > CODE_LINES
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    _mono(p, "\n".join(lines[:CODE_LINES]))
    if cut:
        note = doc.add_paragraph()
        r = note.add_run(f"… 뒤로 {len(lines) - CODE_LINES}줄 더 있습니다. 전체는 결과 화면이나 "
                         "JSON 보고서에서 보세요.")
        r.font.size = Pt(9)
        r.font.color.rgb = GREY


def _table(doc, head, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(head))
    t.style = "Table Grid"
    for c, name in zip(t.rows[0].cells, head):
        c.paragraphs[0].add_run(name).bold = True
    for row in rows:
        cells = t.add_row().cells
        for c, v in zip(cells, row):
            c.text = ""
            p = c.paragraphs[0]
            if v.startswith("`") and v.endswith("`"):
                _mono(p, v.strip("`"))
            else:
                p.add_run(v)
    if widths:
        for row in t.rows:
            for c, w in zip(row.cells, widths):
                c.width = w
    return t


def build(t, rows, exchanges, meta, path):
    """보고서 한 벌을 만들어 `path`(파일 객체나 경로)에 쓴다.

    t·rows·exchanges 는 `_report_rows` 가 주는 것 그대로, meta 는 화면이 아는 값
    (프로젝트 이름·역할·작성 시각·연습용인지·모듈 이름·CVSS 계산·ATT&CK 주소)이다.
    """
    doc = Document()
    doc.styles["Normal"].font.size = Pt(10)

    doc.add_heading(("연습 기록 — " if meta["practice"] else "점검 결과 — ") + t["name"], level=0)
    if meta["practice"]:
        p = doc.add_paragraph()
        r = p.add_run("점검 결과가 아닙니다. 우리가 띄운 연습용 가짜 서버에서 나온 기록입니다. "
                      "보고서에 넣지 마세요.")
        r.bold = True
    for line in [f'도구: 딸깍이 (DAST 대시보드)', f'프로젝트: {meta["project"]}',
                 f'대상: {t["url"]}' + (f' ({meta["role"]})' if meta["role"] else ""),
                 f'작성: {meta["written"]} (KST)', f'발견: {len(rows)}건']:
        doc.add_paragraph(line, style="List Bullet")

    doc.add_heading("한눈에", level=1)
    _table(doc, ["#", "심각도", "항목", "위치", "ATT&CK", "상태"],
           [[str(i), m["severity"], m["title"], "`" + m["location"] + "`", m["technique"], m["status"]]
            for i, m in enumerate(meta["summary"], 1)])
    note = doc.add_paragraph()
    r = note.add_run("위치는 어디서 났는지 적어 둔 주소입니다 — 눌러 보는 링크가 아닙니다. "
                     "브라우저로 그대로 열면 로그인이 필요하다고 하거나 데이터(JSON)만 나옵니다. "
                     "무엇을 보내 무엇을 받았는지는 각 항목의 요청·응답에 그대로 있습니다.")
    r.font.size = Pt(9)
    r.font.color.rgb = GREY

    for i, (r_row, m) in enumerate(zip(rows, meta["items"]), 1):
        doc.add_page_break()
        doc.add_heading(f'{i}. {r_row["title"]}', level=1)
        doc.add_heading("1. 취약점 개요", level=2)
        _table(doc, ["항목", "내용"], [
            ["취약점명", r_row["title"]],
            ["점검대상", f'{t["name"]} ({t["url"]})'],
            ["발견 경로", "`" + r_row["location"] + "`"],
            ["취약점 설명", m["description"]],
            ["영향도(CVSS 3.1)", m["impact"]],
            ["CVSS Vector", m["vector"]],
            ["발견 모듈", m["module"]],
            ["ATT&CK", m["attack"]],
            ["상태", m["status"]],
        ])
        doc.add_heading("2. 취약점 상세설명", level=2)
        _code(doc, r_row["evidence"], "근거")
        x = exchanges.get(r_row["id"])
        if x:
            _code(doc, x["request"], "요청")
            _code(doc, x["response"], "응답(앞부분)")
        doc.add_heading("3. 악용 시나리오", level=2)
        p = doc.add_paragraph()
        rr = p.add_run("여기는 사람이 씁니다 — 이 결과로 무엇을 할 수 있는지.")
        rr.italic = True
        rr.font.color.rgb = GREY
        doc.add_heading("4. 조치방안", level=2)
        doc.add_paragraph(r_row["recommendation"] or "—")

    for p in doc.paragraphs:
        if p.style.name == "Normal":
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.save(path)
    return doc
