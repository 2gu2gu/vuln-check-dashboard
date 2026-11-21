"""점검 결과를 Word(.docx) 로 낸다 — 팀 결과보고서 **템플릿 통합본** 그대로.

왜 여기서 따로 만드나. 작업공간에는 공용 변환기(`md2docx` 스킬)가 있지만 그건 내 컴퓨터의
CLI 다. 대시보드는 EC2-4 에서 돌고 거기에는 Node 도 그 스킬도 없다. 그래서 서버에서 바로
만들 수 있는 python-docx 로 그린다. 마크다운을 거치지 않는다 — 글자로 한 번 바꿨다 다시
읽으면 표 안의 `|` 가 깨진다.

**틀과 서식은 `01_제출물/결과보고서_양식/1_결과보고서_템플릿_통합.docx` 에서 그대로 읽어 왔다**
(11-22 사용자 지적: 문서가 전혀 다르다). 디자인 기준은 노션 '보고서 디자인 레퍼런스' —
서체 Noto Sans KR(Word 대안), 코드 모노, 색 셋에 채도를 한 단계 낮춘 위험도 색.

    표지        윗말 + 큰 제목 + 한 줄 설명 + 묶음 글 + 표지 정보 표
    3-2         위험도 적용 결과 (유형마다 항목 코드·건수·최고 CVSS·위험도)
    4-2         대상별 취약점 요약 (등급별 건수·분포 막대·유형 목록)
    5  Part A   5-1 진단 방법, 5-2 유형마다 개요 표·건별 목록·대표 PoC(요청·응답)

나머지 장(1·2·4-1·4-3·6·7·8·9)은 사람이 쓴다. 딸깍이가 아는 것만 채우고, 모르는 칸은
`[ ]` 로 비워 보여 준다 — 빈칸이 보여야 잊지 않는다. 한 파일은 **대상 하나**다.
"""
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

# ── 템플릿에서 읽어 온 서식 ────────────────────────────────
FONT = "Noto Sans KR"
MONO = "Consolas"
INK = RGBColor(0x1C, 0x1C, 0x1C)       # 본문
SUB = RGBColor(0x55, 0x53, 0x4E)       # 보조
FAINT = RGBColor(0x8A, 0x87, 0x7F)     # 흐린 말(표 위 작은 글)
ACCENT = RGBColor(0x2F, 0x5B, 0x63)    # 장 제목·윗말
PAPER = RGBColor(0xE9, 0xE7, 0xE1)     # 어두운 코드 블록 위의 글자
HOLE = RGBColor(0x9C, 0x3E, 0x39)      # 사람이 채울 자리
HEAD_FILL = "ECEAE4"                   # 표 머리 칸
RULE = "D9D6CE"                        # 표 안쪽 가로줄
CODE_FILL = "1C1C1C"                   # 코드 블록 바탕
# 위험도 색 — 템플릿 4-2 머리 칸에서 그대로
SEV_COLOR = {"Critical": "9C3E39", "High": "B26A3C", "Medium": "A88B35",
             "Low": "5E7C5A", "Info": "7B7F86"}
CODE_LINES = 40                        # 요청·응답은 앞부분만. 통째로 넣으면 문서가 코드로 덮인다


# ── 글자 ─────────────────────────────────────────────────

def _font(run, name=FONT):
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


def _line(par, ratio):
    par.paragraph_format.line_spacing = ratio
    par.paragraph_format.line_spacing_rule = WD_LINE_SPACING.MULTIPLE
    return par


def _say(doc, text, size=10, color=INK, bold=False, ratio=1.6, space=4, font=FONT):
    p = _line(doc.add_paragraph(), ratio)
    p.paragraph_format.space_after = Pt(space)
    r = _font(p.add_run(text), font)
    r.font.size = Pt(size)
    r.font.color.rgb = color
    r.bold = bold
    return p


def _bullet(doc, text, color=INK):
    p = _line(doc.add_paragraph(style="List Paragraph"), 1.6)
    p.paragraph_format.space_after = Pt(2)
    r = _font(p.add_run("· " + text))
    r.font.size = Pt(10)
    r.font.color.rgb = color
    return p


def _hole(doc, text):
    return _bullet(doc, text, color=HOLE)


def _head(doc, text, level):
    """장(2) · 절(3) · 유형(4). 크기·색은 템플릿 값."""
    size, color = {2: (17, ACCENT), 3: (12.5, INK), 4: (11, INK)}[level]
    p = _line(doc.add_paragraph(style=f"Heading {level}"), 1.2)
    p.paragraph_format.space_before = Pt(14 if level == 2 else 10)
    p.paragraph_format.space_after = Pt(6)
    r = _font(p.add_run(text))
    r.font.size = Pt(size)
    r.font.color.rgb = color
    r.bold = True
    return p


# ── 표 ──────────────────────────────────────────────────

def _shade(cell, color):
    sh = OxmlElement("w:shd")
    sh.set(qn("w:val"), "clear")
    sh.set(qn("w:fill"), color)
    cell._tc.get_or_add_tcPr().append(sh)


def _rules(t):
    """위아래만 굵게, 안쪽은 얇은 가로줄, 세로줄 없음 — 템플릿의 표."""
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


def _cell(cell, text, size=9, color=INK, bold=False, mono=False):
    p = _line(cell.paragraphs[0], 1.3)
    p.paragraph_format.space_after = Pt(2)
    r = _font(p.add_run(text), MONO if mono else FONT)
    r.font.size = Pt(size)
    r.font.color.rgb = color
    r.bold = bold
    return r


def _table(doc, head, rows, head_colors=None):
    """머리 칸은 크림색 바탕에 보조색 글씨. `■` 가 붙은 머리는 위험도 색으로 적는다."""
    t = doc.add_table(rows=1, cols=len(head))
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    _rules(t)
    for i, (c, name) in enumerate(zip(t.rows[0].cells, head)):
        _shade(c, HEAD_FILL)
        color = SUB
        if head_colors and head_colors.get(name):
            color = RGBColor.from_string(head_colors[name])
        _cell(c, name, size=9, color=color, bold=True)
    for row in rows:
        cells = t.add_row().cells
        for c, v in zip(cells, row):
            v = "" if v is None else str(v)
            mono = v.startswith("`") and v.endswith("`") and len(v) > 1
            color = INK
            if v.strip() == "[ ]":
                color = HOLE
            elif v.endswith("(제안)"):
                color = SUB
            elif v in SEV_COLOR:
                color = RGBColor.from_string(SEV_COLOR[v])
            _cell(c, v.strip("`") if mono else v, size=8.5 if mono else 9, color=color, mono=mono)
    return t


def _bar(doc, counts):
    """등급별 건수를 칸 너비로 그린 분포 막대 — 템플릿 4-2 의 그 줄."""
    live = [(k, n) for k, n in counts.items() if n]
    if not live:
        return None
    t = doc.add_table(rows=1, cols=len(live))
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    total = sum(n for _k, n in live)
    width = Cm(16.0)
    for c, (k, n) in zip(t.rows[0].cells, live):
        _shade(c, SEV_COLOR[k])
        c.width = Cm(round(16.0 * n / total, 2))
        _cell(c, f"{k} {n}", size=8, color=PAPER, bold=True)
    del width
    return t


# ── 코드 블록 ─────────────────────────────────────────────

def _code(doc, text, head=""):
    """요청·응답처럼 그대로 보여야 하는 토막 — 어두운 바탕에 밝은 글씨(템플릿 모양)."""
    if head:
        _say(doc, head, size=8.5, color=FAINT, ratio=1.25, space=2)
    lines = (text or "").splitlines() or [""]
    cut = lines[CODE_LINES:]
    p = _line(doc.add_paragraph(), 1.25)
    p.paragraph_format.space_after = Pt(6)
    pr = p._p.get_or_add_pPr()
    sh = OxmlElement("w:shd")
    sh.set(qn("w:val"), "clear")
    sh.set(qn("w:fill"), CODE_FILL)
    pr.append(sh)
    r = _font(p.add_run(), MONO)
    r.font.size = Pt(9)
    r.font.color.rgb = PAPER
    for i, line in enumerate(lines[:CODE_LINES]):
        if i:
            r.add_break()
        r.add_text(line)
    if cut:
        _say(doc, f"뒤로 {len(cut)}줄 더 있습니다. 전체는 결과 화면이나 JSON 보고서에 있습니다.",
             size=8.5, color=FAINT, ratio=1.25, space=6)
    return p


# ── 판 깔기 ──────────────────────────────────────────────

def _dress(doc):
    st = doc.styles["Normal"]
    st.font.size = Pt(10)
    st.font.color.rgb = INK
    st.font.name = FONT
    st.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    for sec in doc.sections:
        sec.top_margin, sec.bottom_margin = Cm(2.6), Cm(2.4)
        sec.left_margin = sec.right_margin = Cm(2.3)
        p = sec.header.paragraphs[0]
        p.text = ""
        r = _font(p.add_run("취약점 진단 및 모의해킹 결과 보고서    대외비 · 팀 내부용"))
        r.font.size = Pt(8)
        r.font.color.rgb = FAINT


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


# ── 문서 ─────────────────────────────────────────────────

def build(doc_meta, items, path):
    doc = Document()
    _dress(doc)
    groups = _groups(items)
    labels = ("Critical", "High", "Medium", "Low", "Info")
    counts = {k: 0 for k in labels}
    for it in items:
        if it["severity_label"] in counts:
            counts[it["severity_label"]] += 1

    # ── 표지 ──────────────────────────────────────────
    _say(doc, "RESULT REPORT  ·  딸깍이 자동 생성", size=10, color=ACCENT, bold=True, ratio=1.2, space=10)
    title = _line(doc.add_paragraph(style="Heading 1"), 1.1)
    r = _font(title.add_run("취약점 진단 및\n모의해킹 결과 보고서"))
    r.font.size = Pt(30)
    r.font.color.rgb = INK
    r.bold = True
    _say(doc, f'{doc_meta["url"]}  |  {doc_meta["zone"]} {doc_meta["asset_id"]} {doc_meta["target_name"]}',
         size=11, color=SUB, ratio=1.25, space=14)
    if doc_meta["practice"]:
        _say(doc, "점검 결과가 아닙니다. 연습용 가짜 서버에서 나온 기록입니다. 보고서에 넣지 마세요.",
             size=10, color=HOLE, bold=True)
    _bullet(doc, "채운 절: 3-2 위험도 적용 결과 · 4-2 대상별 취약점 요약 · 5 Part A 진단 상세 결과")
    _bullet(doc, "나머지 장(1 개요, 2 진단 항목, 4-1 총평, 6 Part B, 7 보안 대책)은 사람이 씁니다")
    _bullet(doc, "기준: KISA 기술적 취약점 상세가이드 2026, OWASP Top 10:2025, CVSS 3.1")
    _hole(doc, "대괄호 [ ] 는 딸깍이가 알 수 없는 칸입니다 — 사람이 채웁니다")

    _say(doc, "표지 정보", size=9, color=FAINT, bold=True, ratio=1.2, space=4)
    _table(doc, ["항목", "내용"], [
        ["문서명", "취약점 진단 및 모의해킹 결과 보고서"],
        ["프로젝트", doc_meta["project"]],
        ["대상", f'{doc_meta["target_name"]} ({doc_meta["url"]})'],
        ["자산 ID / 구역", f'{doc_meta["asset_id"]} / {doc_meta["zone"]}'],
        ["작성", f'{doc_meta["written"]} (KST)'],
        ["작성 도구", doc_meta["tool"]],
        ["발견 건수", f'{len(items)}건 · 유형 {len(groups)}가지'],
        ["문서 버전", "[ ]"],
        ["보안 등급", "대외비 (팀 내부용)"],
    ])

    # ── 3 위험도 ──────────────────────────────────────
    doc.add_page_break()
    _head(doc, "3  위험도 평가 기준 및 적용 결과", 2)
    _head(doc, "3-2. 위험도 적용 결과", 3)
    _say(doc, f'[{doc_meta["zone"]}] {doc_meta["asset_id"]} {doc_meta["target_name"]} ({doc_meta["url"]})',
         size=10, space=6)
    _table(doc, ["V-ID", "취약점 유형", "항목 코드", "건수", "CVSS (최고)", "위험도"],
           [[vid, g[0]["module_name"], g[0]["kisa"] or "[ ]", f"{len(g)}건", _top_cvss(g),
             g[0]["top_severity"]] for vid, g in groups])
    _say(doc, "CVSS 에 (제안) 이 붙은 것은 모듈이 제안한 값입니다. 화면에서 벡터를 확정하면 떨어집니다.",
         size=8.5, color=FAINT, ratio=1.25, space=10)

    # ── 4 요약 ────────────────────────────────────────
    _head(doc, "4  진단 결과 요약", 2)
    _head(doc, "4-2. 대상별 취약점 요약", 3)
    _table(doc, ["구역", "자산 ID", "대상", "■ Critical", "■ High", "■ Medium", "■ Low", "■ Info", "합계"],
           [[doc_meta["zone"], doc_meta["asset_id"], doc_meta["target_name"],
             counts["Critical"], counts["High"], counts["Medium"], counts["Low"], counts["Info"], len(items)]],
           head_colors={f"■ {k}": v for k, v in SEV_COLOR.items()})
    _bar(doc, counts)
    _say(doc, "※ 건수는 건 단위(V-xx-n) 기준입니다. 오탐으로 내린 것은 빠져 있고, "
              "일부러 심어 둔 취약점이 몇 건인지는 사람이 가려 적습니다.",
         size=8.5, color=FAINT, ratio=1.25, space=10)
    _say(doc, "취약점 유형 목록:", size=10, space=4)
    _table(doc, ["V-ID", "취약점 유형", "대상", "건수", "최고 위험도", "시나리오 사용", "상세 / 대책"],
           [[vid, g[0]["module_name"], doc_meta["asset_id"], f"{len(g)}건", g[0]["top_severity"], "[ ]",
             "5-2 / 7-3"] for vid, g in groups])

    # ── 5 Part A ─────────────────────────────────────
    doc.add_page_break()
    _head(doc, "5  Part A. 진단 상세 결과", 2)
    _bullet(doc, "서술 순서: 구역 → 대상 → 취약점 유형(V-xx) → 건(V-xx-n)")
    _bullet(doc, "유형 설명은 1회만 쓰고, 본문에는 대표 PoC 1~2건만 싣습니다")
    _head(doc, "5-1. 진단 방법", 3)
    _table(doc, ["구분", "담당 범위", "도구", "담당자"],
           [["자동 진단", "수집한 지점에 모듈을 돌린 결과", doc_meta["tool"], "[ ]"],
            ["수동 진단", "[ ]", "[ ]", "[ ]"]])
    _say(doc, "※ 자동 진단 결과는 수동 재현으로 확인된 것만 건으로 등록합니다 — 아래 '상태' 가 확인됨인 것입니다.",
         size=8.5, color=FAINT, ratio=1.25, space=10)

    # 대상 하나가 5-2 한 절이고, 유형(V-xx)은 그 안에서 반복한다 — 템플릿의 짜임 그대로
    _head(doc, f'5-2. [{doc_meta["zone"]}] 구역 — {doc_meta["asset_id"]} {doc_meta["target_name"]}', 3)
    for n, (vid, g) in enumerate(groups, 1):
        if n > 1:
            doc.add_page_break()
        _head(doc, f'{vid}. {g[0]["module_name"]}', 4)
        _table(doc, ["항목", "내용"], [
            ["위험도", f'{g[0]["top_severity"]} (건 중 최고, CVSS {_top_cvss(g)})'],
            ["CVSS Vector", g[0]["cvss_vector"] or "[ ]"],
            ["항목 코드 / CWE", f'{g[0]["kisa"] or "[ ]"} / [ ]'],
            ["OWASP 2025", g[0]["owasp"] or "[ ]"],
            ["건수", f"{len(g)}건"],
            ["발견 방법", f'자동(딸깍이 — {g[0]["module_name"]})'],
            ["보안 대책", "7-3 참조 — " + (g[0]["recommendation"] or "[ ]").split(".")[0][:80]],
        ])
        _bullet(doc, "설명: " + (g[0]["module_desc"] or "")[:400])
        _hole(doc, "위험 평가 설명: [악용 전제 조건과 난이도, 등급 산정 근거]")
        _hole(doc, "영향: [기밀성 · 무결성 · 가용성 · 금전 · 평판 · 규제 중 해당하는 것]")

        _say(doc, "건별 목록:", size=10, space=4)
        _table(doc, ["건 ID", "위치 (URL · 파라미터)", "메서드", "위험도", "의도적", "시나리오 사용",
                     "탐지 검증", "증거", "상태"],
               [[f"{vid}-{k}", "`" + it["location"] + "`", it["method"], it["severity_label"],
                 "[ ]", "[ ]", "[ ]", ("요청·응답 수록" if it["request"] else "근거만"), it["status_label"]]
                for k, it in enumerate(g, 1)])

        rep = next((i for i in g if i["request"]), g[0])
        _say(doc, f'대표 PoC ({vid}-{g.index(rep) + 1}): {rep["title"]}', size=10, space=4)
        _hole(doc, "재현 단계: [1. 2. 3. 사람이 적습니다]")
        _code(doc, rep["evidence"], "근거")
        if rep["request"]:
            _code(doc, rep["request"], "요청 발췌")
            _code(doc, rep["response"], "응답 발췌")
        _say(doc, "조치방안: " + (rep["recommendation"] or "[ ]"), size=10, space=10)

    doc.save(path)
    return doc
