"""점검 결과를 Word(.docx) 로 낸다 — 팀 결과보고서 양식 그대로(11-21 사용자 지시).

왜 여기서 따로 만드나. 작업공간에는 공용 변환기(`md2docx` 스킬)가 있지만 그건 **내 컴퓨터의
CLI** 다. 대시보드는 EC2-4 에서 돌고 거기에는 Node 도 그 스킬도 없다. 그래서 서버에서 바로
만들 수 있는 python-docx 로 그린다. 마크다운을 거치지 않는다 — 글자로 한 번 바꿨다 다시
읽으면 표 안의 `|` 가 깨진다.

**틀은 `01_제출물/결과보고서_양식/1_결과보고서_양식.md` 다.** 그 양식에서 딸깍이가 **실제로
아는 것** 만 채운다.

    3-2. 위험도 적용 결과        유형마다 건수·최고 CVSS·위험도
    4-2. 대상별 취약점 요약      등급별 건수와 합계, 유형 목록
    5.   Part A 진단 상세 결과   유형마다 개요 표·건별 목록·대표 PoC(요청·응답)

나머지(총평, 목표 달성, 시나리오, 진단 인력, 이행 점검)는 **사람이 쓴다.** 대신 자리를
`[ ]` 로 비워 두고 무엇을 채워야 하는지 적어 둔다 — 빈칸이 있다는 걸 보여야 잊지 않는다.

한 파일은 **대상 하나** 다. 보고서 한 벌은 대상별 파일을 모아 사람이 엮는다.
"""
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import Cm, Pt, RGBColor

# ── 미감 양식의 서식(11-22 사용자 지시: 우리 미감 양식과 맞춰줘) ──────────────
# `01_제출물/결과보고서_양식/1_결과보고서_양식_미감적용.docx` 에서 그대로 읽어 온 값이다.
# 글꼴 Noto Sans KR, 본문 9.5pt, 제목 16/13/12pt, 표는 **가로줄만**(위아래 굵게, 안쪽 얇게,
# 세로줄 없음), 머리 칸 배경 크림색. 색은 거의 검정 본문에 회색 보조, 강조는 청록 하나.
BODY_FONT = "Noto Sans KR"
MONO = "Consolas"
INK = RGBColor(0x1C, 0x1C, 0x1C)      # 본문
SUB = RGBColor(0x55, 0x53, 0x4E)      # 보조 설명
FAINT = RGBColor(0x8A, 0x87, 0x7F)    # 흐린 것
ACCENT = RGBColor(0x2F, 0x5B, 0x63)   # 강조(청록)
HOLE = RGBColor(0x9C, 0x3E, 0x39)     # 사람이 채울 자리 — 양식의 경고색
HEAD_FILL = "ECEAE4"                  # 표 머리 칸 배경
RULE = "D9D6CE"                       # 표 안쪽 가로줄
GREY = SUB                            # 옛 이름(쓰던 자리 유지)
CODE_LINES = 40                       # 요청·응답은 앞부분만. 통째로 넣으면 문서가 코드로 덮인다


def _font(run, name):
    """한글은 eastAsia 까지 적어야 Word 가 그 글꼴로 그린다."""
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts")
        rpr.append(rf)
    for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        rf.set(qn(a), name)
    return run


def _dress(doc):
    """미감 양식의 판을 깐다 — 글꼴·크기·색·여백·머리말."""
    st = doc.styles["Normal"]
    st.font.size = Pt(9.5)
    st.font.color.rgb = INK
    st.font.name = BODY_FONT
    st.element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
    for name, size in (("Title", 28), ("Heading 1", 16), ("Heading 2", 13), ("Heading 3", 12)):
        s = doc.styles[name]
        s.font.name = BODY_FONT
        s.font.size = Pt(size)
        s.font.color.rgb = INK
        if s.element.rPr is not None and s.element.rPr.rFonts is not None:
            s.element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
    for sec in doc.sections:
        sec.top_margin, sec.bottom_margin = Cm(2.6), Cm(2.4)
        sec.left_margin = sec.right_margin = Cm(2.3)
        p = sec.header.paragraphs[0]
        p.text = ""
        r = _font(p.add_run("취약점 진단 및 모의해킹 결과 보고서    대외비 · 팀 내부용"), BODY_FONT)
        r.font.size = Pt(8)
        r.font.color.rgb = FAINT


def _mono(p, text, size=9):
    r = _font(p.add_run(text), MONO)
    r.font.size = Pt(size)
    r.font.color.rgb = INK
    return r


def _small(doc, text, color=SUB, italic=False):
    p = doc.add_paragraph()
    r = _font(p.add_run(text), BODY_FONT)
    r.font.size = Pt(8.5)
    r.font.color.rgb = color
    r.italic = italic
    return p


def _hole(doc, text):
    """사람이 채울 자리."""
    return _small(doc, text, color=HOLE)


def _code(doc, text, head=""):
    if head:
        doc.add_paragraph().add_run(head).bold = True
    lines = (text or "").splitlines() or [""]
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    _mono(p, "\n".join(lines[:CODE_LINES]))
    if len(lines) > CODE_LINES:
        _small(doc, f"뒤로 {len(lines) - CODE_LINES}줄 더 있습니다. 전체는 결과 화면이나 JSON 보고서에 있습니다.")


def _rules(t):
    """표 테두리를 미감 양식대로 — 위아래만 굵게, 안쪽은 얇은 가로줄, 세로줄은 없다."""
    pr = t._tbl.tblPr
    old = pr.find(qn("w:tblBorders"))
    if old is not None:
        pr.remove(old)
    b = OxmlElement("w:tblBorders")
    for edge, val, sz, color in (("top", "single", "12", "1C1C1C"), ("bottom", "single", "12", "1C1C1C"),
                                 ("left", "nil", "0", "auto"), ("right", "nil", "0", "auto"),
                                 ("insideH", "single", "4", RULE), ("insideV", "nil", "0", "auto")):
        e = OxmlElement(f"w:{edge}")
        e.set(qn("w:val"), val)
        e.set(qn("w:sz"), sz)
        e.set(qn("w:space"), "0")
        e.set(qn("w:color"), color)
        b.append(e)
    pr.append(b)


def _fill(cell, color):
    sh = OxmlElement("w:shd")
    sh.set(qn("w:val"), "clear")
    sh.set(qn("w:fill"), color)
    cell._tc.get_or_add_tcPr().append(sh)


def _table(doc, head, rows):
    t = doc.add_table(rows=1, cols=len(head))
    _rules(t)
    for c, name in zip(t.rows[0].cells, head):
        _fill(c, HEAD_FILL)
        r = _font(c.paragraphs[0].add_run(name), BODY_FONT)
        r.bold = True
        r.font.size = Pt(9)
    for row in rows:
        cells = t.add_row().cells
        for c, v in zip(cells, row):
            v = "" if v is None else str(v)
            p = c.paragraphs[0]
            if v.startswith("`") and v.endswith("`") and len(v) > 1:
                _mono(p, v.strip("`"), size=8.5)
            else:
                r = _font(p.add_run(v), BODY_FONT)
                r.font.size = Pt(9)
                r.font.color.rgb = HOLE if v.strip() == "[ ]" else INK
                if v.endswith("(제안)"):
                    r.font.color.rgb = SUB      # 사람이 확정하지 않은 값은 흐리게
    return t


def _method_of(request: str) -> str:
    """요청 첫 줄에서 메서드를 읽는다 — 결과에는 따로 안 들고 있다."""
    head = (request or "").lstrip().split(" ", 1)[0]
    return head if head in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") else "[ ]"


def _top_cvss(group):
    """그 유형에서 가장 높은 점수. '(제안)' 이 붙은 값도 숫자로 견준다."""
    best, top = "", -1.0
    for it in group:
        head = (it["cvss_score"] or "").split(" ")[0]
        try:
            n = float(head)
        except ValueError:
            continue
        if n > top:
            top, best = n, it["cvss_score"]
    return best or "[ ]"


def _groups(items):
    """같은 모듈이 찾은 것끼리 묶는다 — 양식의 '취약점 유형(V-xx)' 한 칸이 모듈 하나다."""
    order, by = [], {}
    for it in items:
        if it["module_id"] not in by:
            by[it["module_id"]] = []
            order.append(it["module_id"])
        by[it["module_id"]].append(it)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    order.sort(key=lambda mid: (min(rank.get(i["severity"], 9) for i in by[mid]), -len(by[mid])))
    return [(f"V-{n:02d}", by[mid]) for n, mid in enumerate(order, 1)]


def build(doc_meta, items, path):
    """보고서 한 벌을 만들어 `path`(파일 객체나 경로)에 쓴다.

    doc_meta 는 표지에 들어갈 것(대상·자산 ID·구역·작성 시각·도구 판), items 는 결과 한 줄씩
    — 둘 다 routes 가 DB 와 모듈에서 꺼내 넘긴다.
    """
    doc = Document()
    _dress(doc)
    groups = _groups(items)
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for it in items:
        if it["severity"] in counts:
            counts[it["severity"]] += 1

    # ── 표지 ──────────────────────────────────────────────
    doc.add_heading("취약점 진단 및 모의해킹 결과 보고서", level=0)
    if doc_meta["practice"]:
        p = doc.add_paragraph()
        p.add_run("점검 결과가 아닙니다. 연습용 가짜 서버에서 나온 기록입니다. 보고서에 넣지 마세요.").bold = True
    _table(doc, ["항목", "내용"], [
        ["대상", f'{doc_meta["target_name"]} ({doc_meta["url"]})'],
        ["자산 ID", doc_meta["asset_id"]],
        ["구역", doc_meta["zone"]],
        ["프로젝트", doc_meta["project"]],
        ["작성", f'{doc_meta["written"]} (KST)'],
        ["작성 도구", doc_meta["tool"]],
        ["발견 건수", f'{len(items)}건 (유형 {len(groups)}가지)'],
    ])
    _small(doc, "이 문서는 결과보고서 양식 가운데 딸깍이가 아는 것(3-2, 4-2, 5장)만 채운 것입니다. "
                "총평·목표 달성·시나리오·진단 인력·이행 점검은 사람이 씁니다.")
    _hole(doc, "[ ] 로 적힌 칸은 딸깍이가 알 수 없는 것입니다 — 사람이 채웁니다.")

    # ── 3-2 위험도 적용 결과 ──────────────────────────────
    doc.add_heading("3-2. 위험도 적용 결과", level=1)
    doc.add_paragraph(f'[{doc_meta["zone"]}] {doc_meta["asset_id"]} {doc_meta["target_name"]} ({doc_meta["url"]})')
    _table(doc, ["V-ID", "취약점 유형", "항목 코드", "건수", "CVSS (최고)", "위험도"],
           [[vid, g[0]["module_name"], g[0]["kisa"] or "[ ]", f"{len(g)}건", _top_cvss(g),
             g[0]["top_severity"]] for vid, g in groups])

    # ── 4-2 대상별 취약점 요약 ────────────────────────────
    doc.add_heading("4-2. 대상별 취약점 요약", level=1)
    _table(doc, ["구역", "자산 ID", "대상", "Critical", "High", "Medium", "Low", "Info", "합계"],
           [[doc_meta["zone"], doc_meta["asset_id"], doc_meta["target_name"],
             counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"], len(items)]])
    _small(doc, "건수는 건 단위(V-xx-n) 기준입니다. 오탐으로 내린 것은 빠져 있습니다. "
                "일부러 심어 둔 취약점이 몇 건인지는 사람이 가려 적습니다.")
    doc.add_paragraph("취약점 유형 목록:")
    _table(doc, ["V-ID", "취약점 유형", "대상", "건수", "최고 위험도", "시나리오 사용", "상세 / 대책"],
           # 5-1 은 진단 방법이라 유형은 5-2 부터다
           [[vid, g[0]["module_name"], doc_meta["asset_id"], f"{len(g)}건", g[0]["top_severity"], "[ ]",
             f"5-{n} / 7-3"] for n, (vid, g) in enumerate(groups, 2)])

    # ── 5. Part A 진단 상세 결과 ──────────────────────────
    doc.add_heading("5. Part A. 진단 상세 결과", level=1)
    doc.add_heading("5-1. 진단 방법", level=2)
    _table(doc, ["구분", "담당 범위", "도구", "담당자"],
           [["자동 진단", "딸깍이 모듈이 보는 범위(수집한 지점에 모듈을 돌린 결과)", doc_meta["tool"], "[ ]"],
            ["수동 진단", "[ ]", "[ ]", "[ ]"]])
    _small(doc, "자동 진단 결과는 수동 재현으로 확인된 것만 건으로 등록합니다. "
                "아래 '상태' 칸이 확인됨인 것이 그것입니다.")

    for n, (vid, g) in enumerate(groups, 2):
        doc.add_page_break()
        doc.add_heading(f'5-{n}. {vid}. {g[0]["module_name"]}', level=2)
        _table(doc, ["항목", "내용"], [
            ["위험도", f'{g[0]["top_severity"]} (건 중 최고, CVSS {_top_cvss(g)})'],
            ["CVSS Vector", g[0]["cvss_vector"] or "[ ]"],
            ["항목 코드 / CWE", f'{g[0]["kisa"] or "[ ]"} / [ ]'],
            ["OWASP 2025", g[0]["owasp"] or "[ ]"],
            ["건수", f"{len(g)}건"],
            ["발견 방법", f'자동(딸깍이 — {g[0]["module_name"]})'],
            ["보안 대책", "7-3 참조 — " + (g[0]["recommendation"] or "[ ]").split(".")[0][:80]],
        ])
        doc.add_paragraph("설명: " + (g[0]["module_desc"] or ""))
        _hole(doc, "위험 평가 설명: [악용 전제 조건과 난이도, 등급 산정 근거를 사람이 적습니다]")
        _hole(doc, "영향: [기밀성 · 무결성 · 가용성 · 금전 · 평판 · 규제 중 해당하는 것]")

        doc.add_paragraph("건별 목록:")
        _table(doc, ["건 ID", "위치 (URL · 파라미터)", "메서드", "위험도", "의도적", "시나리오 사용",
                     "탐지 검증", "증거", "상태"],
               [[f"{vid}-{k}", "`" + it["location"] + "`", it["method"], it["severity_label"],
                 "[ ]", "[ ]", "[ ]", ("요청·응답 수록" if it["request"] else "근거만"), it["status_label"]]
                for k, it in enumerate(g, 1)])

        rep = next((i for i in g if i["request"]), g[0])
        doc.add_paragraph(f'대표 PoC ({vid}-{g.index(rep) + 1}): {rep["title"]}')
        _code(doc, rep["evidence"], "근거")
        if rep["request"]:
            _code(doc, rep["request"], "요청")
            _code(doc, rep["response"], "응답(앞부분)")
        _hole(doc, "재현 단계: [1. 2. 3. 사람이 적습니다 — 위 요청을 그대로 보내면 되는 경우에도 한 줄은 적습니다]")
        doc.add_paragraph("조치방안: " + (rep["recommendation"] or "[ ]"))

    for p in doc.paragraphs:
        if p.style.name == "Normal":
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.save(path)
    return doc
