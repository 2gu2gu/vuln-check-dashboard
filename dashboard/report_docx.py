"""점검 결과를 Word(.docx) 로 낸다 — 팀 결과보고서 **템플릿 통합본** 그대로.

왜 여기서 따로 만드나. 작업공간에는 공용 변환기(`md2docx` 스킬)가 있지만 그건 내 컴퓨터의
CLI 다. 대시보드는 EC2-4 에서 돌고 거기에는 Node 도 그 스킬도 없다. 그래서 서버에서 바로
만들 수 있는 python-docx 로 그린다. 마크다운을 거치지 않는다 — 글자로 한 번 바꿨다 다시
읽으면 표 안의 `|` 가 깨진다.

**틀과 서식은 `01_제출물/결과보고서_양식/1_결과보고서_템플릿_통합.docx` 에서 그대로 읽어 왔다**
(11-22 사용자 지적: 문서가 전혀 다르다). 디자인 기준은 노션 '보고서 디자인 레퍼런스' —
서체 Noto Sans KR(Word 대안), 코드 모노, 색 셋에 채도를 한 단계 낮춘 위험도 색.

    표지        윗말 + 큰 제목 + 한 줄 설명 + 묶음 글 + 표지 정보 표
    3-2         위험도 적용 결과 (대상마다 유형·항목 코드·건수·최고 CVSS·위험도)
    4-1         총평 (지표 칸 넷 · 총평 한 문단 · 그림 셋)
    4-2         대상별 취약점 요약 (구역 소계·합계가 붙은 표 + 취약점 목록)
    5  Part A   5-1 진단 방법, 5-2~ 대상마다 유형 개요 표·건별 목록·대표 PoC(요청·응답)

나머지 장(1·2·6·7·8·9)은 사람이 쓴다. 딸깍이가 아는 것만 채우고, 모르는 칸은
`[ ]` 로 비워 보여 준다 — 빈칸이 보여야 잊지 않는다.

한 파일이 **프로젝트 하나**다(11-22 바뀜). 전에는 대상 하나였는데 그러면 4장 그림이 막대
한 줄짜리가 되어 그림일 까닭이 없었다. 4장은 대상을 모아 보이고 5장만 대상마다 절을 나눈다.
그림은 `report_chart.py` 가 Word 차트로 그린다 — 팀 보고서 생성 도구(`SaeMoi/auto_report`)
가 쓰는 방식과 같다.
"""
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

from . import report_chart

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


def _table(doc, head, rows, head_colors=None, strong=(), widths=None, head_size=9):
    """머리 칸은 크림색 바탕에 보조색 글씨. `■` 가 붙은 머리는 위험도 색으로 적는다.

    strong 은 소계·합계처럼 눌러 읽을 줄 번호(0부터). 바탕을 머리 칸 색으로 깔고 굵게 적는다.
    widths 는 칸 너비(cm). 주지 않으면 Word 가 글자 길이대로 잡는데, 칸이 많은 표에서는
    대상 이름이 석 줄로 접힌다 — 칸이 많은 표에는 꼭 준다.
    """
    t = doc.add_table(rows=1, cols=len(head))
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    _rules(t)
    for i, (c, name) in enumerate(zip(t.rows[0].cells, head)):
        _shade(c, HEAD_FILL)
        color = SUB
        if head_colors and head_colors.get(name):
            color = RGBColor.from_string(head_colors[name])
        if name.startswith("■ "):
            # ■ 는 한글 글꼴에서 한 글자 폭을 다 쓴다. 그대로 두면 '■ Critical' 이 두 줄로 접힌다.
            # 네모만 한 단계 줄이고, 그 칸은 아예 줄바꿈을 막는다 — 등급 이름은 한 줄이어야 읽힌다
            box = _cell(c, "■", size=head_size - 1, color=color, bold=True)
            tail = _font(box._parent.add_run(" " + name[2:]))
            tail.font.size, tail.font.bold, tail.font.color.rgb = Pt(head_size), True, color
            c._tc.get_or_add_tcPr().append(OxmlElement("w:noWrap"))
        else:
            _cell(c, name, size=head_size, color=color, bold=True)
    for n, row in enumerate(rows):
        cells = t.add_row().cells
        for c, v in zip(cells, row):
            if n in strong:
                _shade(c, HEAD_FILL)
            v = "" if v is None else str(v)
            mono = v.startswith("`") and v.endswith("`") and len(v) > 1
            color = INK
            if v.strip() == "[ ]":
                color = HOLE
            elif v.endswith("(제안)"):
                color = SUB
            elif v in SEV_COLOR:
                color = RGBColor.from_string(SEV_COLOR[v])
            _cell(c, v.strip("`") if mono else v, size=8.5 if mono else 9, color=color, mono=mono,
                  bold=n in strong)
    if widths:
        _fixed(t, widths)
    return t


BAR_CM = 15.4


def _bar(doc, counts):
    """등급별 건수를 칸 너비로 그린 분포 막대 — 템플릿 4-2 의 그 줄.

    좁은 칸에 등급 이름까지 넣으면 글자가 접히면서 막대가 두 줄로 부푼다. 칸이 좁으면
    숫자만 적는다.
    """
    live = [(k, n) for k, n in counts.items() if n]
    if not live:
        return None
    t = doc.add_table(rows=1, cols=len(live))
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    total = sum(n for _k, n in live)
    # 아주 작은 칸(1~2건)도 숫자가 접히지 않게 자릿수만큼 바닥을 깔되, 그만큼 전체를 다시 줄인다.
    # 안 그러면 합이 쪽 너비를 넘어 막대가 위 표보다 오른쪽으로 삐져나온다.
    raw = [max(0.5 + 0.25 * len(str(n)), BAR_CM * n / total) for _k, n in live]
    widths = [round(w * BAR_CM / sum(raw), 2) for w in raw]
    pr = t._tbl.tblPr                                      # 칸 안쪽 여백을 줄여 숫자 자리를 번다
    mar = OxmlElement("w:tblCellMar")
    for side, v in (("left", "28"), ("right", "28"), ("top", "0"), ("bottom", "0")):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:w"), v)
        e.set(qn("w:type"), "dxa")
        mar.append(e)
    pr.append(mar)
    for c, (k, n), cm in zip(t.rows[0].cells, live, widths):
        _shade(c, SEV_COLOR[k])
        _cell(c, (f"{k} {n}" if cm >= 2.0 else str(n)), size=8, color=PAPER, bold=True)
    _fixed(t, widths)
    return t


# ── 그림 ────────────────────────────────────────────────
#
# 화면(결과 탭 '점검 현황')에 있는 그림을 보고서에도 같은 모양으로 싣는다(11-22 사용자 요청).
# 막대 그림 자체는 `report_chart.py` 가 Word 차트로 그린다 — 여기서는 그 위에 얹는
# 지표 띠와 그림 제목만 맡는다.


def _fixed(t, widths):
    """Word 의 자동 맞춤을 끄고 칸 너비를 못 박는다 — 안 하면 글자 길이대로 칸이 벌어진다."""
    pr = t._tbl.tblPr
    lay = OxmlElement("w:tblLayout")
    lay.set(qn("w:type"), "fixed")
    pr.append(lay)
    grid = t._tbl.find(qn("w:tblGrid"))
    for col, cm in zip(grid.findall(qn("w:gridCol")), widths):
        col.set(qn("w:w"), str(int(cm * 567)))
    for row in t.rows:
        for c, cm in zip(row.cells, widths):
            c.width = Cm(cm)
    return t


def _cards(doc, cards):
    """지표 띠 — 큰 값 아래 이름. 최종 결과보고서 4-1 맨 위의 그 네 칸이다.

    cards 는 (값, 이름) 목록. 값에 단위를 같이 적는다('7건', '4 / 4곳').

    값 길이는 칸마다 다르다('16개 · 238건' 과 '6건'). 칸을 똑같이 나누면 긴 값이 두 줄로
    접히면서 그 칸만 이름이 아래로 밀린다 — 값 길이에 맞춰 칸을 나누고, 그래도 긴 값은
    글자를 한 단계 줄인다.
    """
    t = doc.add_table(rows=1, cols=len(cards))
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    want = [max(2.4, 0.42 * len(str(big)) + 0.9, 0.22 * len(name) + 0.6) for big, name in cards]
    _fixed(t, [round(w * 16.0 / sum(want), 2) for w in want])
    for c, (big, name) in zip(t.rows[0].cells, cards):
        p = c.paragraphs[0]
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(1)
        r = _font(p.add_run(str(big)))
        r.font.size = Pt(17 if len(str(big)) <= 8 else 14)
        r.font.bold, r.font.color.rgb = True, ACCENT
        p2 = _line(c.add_paragraph(), 1.3)
        p2.paragraph_format.space_after = Pt(4)
        r = _font(p2.add_run(name))
        r.font.size, r.font.color.rgb = Pt(8.5), SUB
    _rules(t)
    _say(doc, "", size=4, space=0)                         # 표 아래 줄과 다음 글이 붙지 않게
    return t


def _figure(doc, title, note=""):
    _say(doc, title, size=9, color=SUB, bold=True, ratio=1.2, space=3)
    if note:
        _say(doc, note, size=8, color=FAINT, ratio=1.2, space=3)


def _callout(doc, lines):
    """요점 상자 — 옅은 바탕에 왼쪽 청록 굵은 선. 총평 문단이 여기 들어간다."""
    out = []
    for i, text in enumerate(lines):
        p = _line(doc.add_paragraph(), 1.45)
        p.paragraph_format.space_before = Pt(6 if i == 0 else 0)
        p.paragraph_format.space_after = Pt(6 if i == len(lines) - 1 else 2)
        p.paragraph_format.left_indent = Pt(10)
        p.paragraph_format.right_indent = Pt(6)
        pr = p._p.get_or_add_pPr()
        sh = OxmlElement("w:shd")
        sh.set(qn("w:val"), "clear")
        sh.set(qn("w:fill"), HEAD_FILL)
        pr.append(sh)
        b = OxmlElement("w:pBdr")
        left = OxmlElement("w:left")
        left.set(qn("w:val"), "single")
        left.set(qn("w:sz"), "24")
        left.set(qn("w:space"), "6")
        left.set(qn("w:color"), "2F5B63")
        b.append(left)
        pr.append(b)
        r = _font(p.add_run(text))
        r.font.size = Pt(10)
        r.font.color.rgb = HOLE if text.startswith("[ ]") else INK
        out.append(p)
    return out


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
    """같은 모듈이 찾은 것끼리 묶는다 — 양식의 '취약점 유형(V-xx)' 한 칸이 모듈 하나다.

    번호는 표에 싣는 순서(위험도 높은 순 → CVSS 높은 순)대로 매긴다. 번호 순서와 표 순서가
    어긋나면 V-01 이 맨 위가 아니어서 읽는 사람이 한 번 걸린다.
    """
    order, by = [], {}
    for it in items:
        if it["module_id"] not in by:
            by[it["module_id"]] = []
            order.append(it["module_id"])
        by[it["module_id"]].append(it)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    order.sort(key=lambda mid: (min(rank.get(i["severity"], 9) for i in by[mid]),
                                -_score(by[mid]), -len(by[mid])))
    return [(f"V-{n:02d}", by[mid]) for n, mid in enumerate(order, 1)]


# ── 문서 ─────────────────────────────────────────────────
#
# 한 파일이 **프로젝트 하나**다(11-22 바뀜). 전에는 대상 하나였는데, 그러면 4장의 그림이
# 막대 한 줄짜리가 되어 그림일 까닭이 없었다. 최종 결과보고서처럼 4장은 대상 전체를 모아 보이고
# 5장만 대상마다 절을 나눈다. V-ID 는 문서 전체에서 한 번만 매겨 3-2·4-2·5장이 같은 번호를 쓴다.

LABELS = ("Critical", "High", "Medium", "Low", "Info")
ZONE_ORDER = ("외부(DMZ)", "관리·내부")
RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _counts(items):
    c = {k: 0 for k in LABELS}
    for it in items:
        if it["severity_label"] in c:
            c[it["severity_label"]] += 1
    return c


def _assets(items):
    """결과에 나온 대상을 구역 → 자산 ID 순으로. 한 줄이 4-2 한 행이고 5장 한 절이다."""
    seen = {}
    for it in items:
        key = it["target_id"]
        if key not in seen:
            seen[key] = {"target_id": key, "asset_id": it["asset_id"], "zone": it["zone"],
                         "name": it["target_name"], "url": it["url"], "items": []}
        seen[key]["items"].append(it)
    return sorted(seen.values(),
                  key=lambda a: (ZONE_ORDER.index(a["zone"]) if a["zone"] in ZONE_ORDER else 9,
                                 a["asset_id"]))


def _score(group):
    head = (_top_cvss(group) or "").split(" ")[0]
    try:
        return float(head)
    except ValueError:
        return -1.0


def _ranked(groups):
    """위험도 높은 순, 같으면 CVSS 높은 순 — 최종 결과보고서 4-2 의 정렬 규칙 그대로."""
    return sorted(groups, key=lambda g: (RANK.get(g[1][0]["top_severity"], 9), -_score(g[1]), g[0]))


def _overall(items, assets, groups):
    """총평 문단 — 집계만으로 적는다.

    최종 결과보고서의 총평은 ① 전체 수준 ② 수와 분포 ③ 공통 원인 ④ 우선 조치 순이다.
    그중 ③ 은 코드를 봐야 아는 것이라 딸깍이가 적으면 틀린 말이 된다 — 비워 보여 준다.
    ②·④ 는 딸깍이가 센 숫자이고, 센 것과 사람이 확인한 것을 섞지 않으려고 상태도 같이 적는다.
    """
    c = _counts(items)
    hit = [a for a in assets if a["items"]]
    worst = max(assets, key=lambda a: len(a["items"]), default=None)
    top = _ranked(groups)[:3]
    open_n = sum(1 for it in items if it["status_label"] == "미확인")
    lines = [f"자동 점검에서 취약점 {len(groups)}개 · {len(items)}건이 나왔음."]
    lines.append(
        f'위험도별로 Critical {c["Critical"]}건, High {c["High"]}건, Medium {c["Medium"]}건, '
        f'Low {c["Low"]}건, 참고 {c["Info"]}건이며, 대상 {len(hit)} / {len(assets)}곳에서 나왔음'
        + (f'(가장 많은 곳은 {worst["asset_id"]} {worst["name"]} {len(worst["items"])}건).'
           if worst and worst["items"] else "."))
    lines.append(f"{len(items) - open_n}건은 사람이 확인했고 {open_n}건은 아직 미확인임 — "
                 "미확인은 재현으로 확인한 뒤 보고서에 올림.")
    if top:
        lines.append("점수가 높은 순으로 먼저 볼 것은 "
                     + ", ".join(f'{v}({g[0]["module_name"]})' for v, g in top) + " 임.")
    return [" ".join(lines),
            "[ ] 공통 원인(입력 미검증 · 서버 측 인가 검증 부재 · 패치 관리 등)은 코드를 보고 사람이 적습니다."]


def _sev_chart(counts):
    return report_chart.column(
        "위험도별 건수", [(k, counts[k]) for k in LABELS],
        [SEV_COLOR[k] for k in LABELS],
        major=1 if max(counts.values(), default=0) <= 8 else None)


def _asset_chart(assets):
    """대상별 위험도 분포 — 건이 있는 대상만, 값이 있는 등급만 싣는다."""
    rows = [a for a in assets if a["items"]]
    if not rows:
        return None
    by = {a["asset_id"]: _counts(a["items"]) for a in rows}
    series = [{"name": k, "values": [by[a["asset_id"]][k] for a in rows], "color": SEV_COLOR[k]}
              for k in LABELS if any(by[a["asset_id"]][k] for a in rows)]
    return report_chart.stacked("대상별 위험도 분포 (건)",
                                [f'{a["asset_id"]} {a["name"]}' for a in rows], series)


def _owasp_chart(owasp):
    """취약점 유형별 — 화면 '점검 현황' 에 있는 그림. 한 건도 없는 유형은 줄을 빼 둔다."""
    rows = [r for r in owasp if r["total"]]
    if not rows:
        return None
    series = [{"name": k, "values": [r["counts"].get(k, 0) for r in rows], "color": SEV_COLOR[k]}
              for k in LABELS if any(r["counts"].get(k) for r in rows)]
    return report_chart.stacked("취약점 유형별 — OWASP Top 10 2025 (건)",
                                [r["name"] for r in rows], series)


def _cover(doc, doc_meta, items, assets, groups):
    _say(doc, "RESULT REPORT  ·  딸깍이 자동 생성", size=10, color=ACCENT, bold=True, ratio=1.2, space=10)
    title = _line(doc.add_paragraph(style="Heading 1"), 1.1)
    r = _font(title.add_run("취약점 진단 및\n모의해킹 결과 보고서"))
    r.font.size = Pt(30)
    r.font.color.rgb = INK
    r.bold = True
    _say(doc, f'{doc_meta["project"]}  |  대상 {len(assets)}곳 · 취약점 {len(groups)}개 · {len(items)}건',
         size=11, color=SUB, ratio=1.25, space=14)
    if doc_meta["practice"]:
        _say(doc, "점검 결과가 아닙니다. 연습용 가짜 서버에서 나온 기록입니다. 보고서에 넣지 마세요.",
             size=10, color=HOLE, bold=True)
    _bullet(doc, "채운 절: 3-2 위험도 적용 결과 · 4-1 총평 · 4-2 대상별 취약점 요약 · 5 Part A 진단 상세 결과")
    _bullet(doc, "나머지 장(1 개요, 2 진단 항목, 6 Part B, 7 보안 대책)은 사람이 씁니다")
    _bullet(doc, "기준: KISA 기술적 취약점 상세가이드 2026, OWASP Top 10:2025, CVSS 3.1")
    _hole(doc, "대괄호 [ ] 는 딸깍이가 알 수 없는 칸입니다 — 사람이 채웁니다")

    _say(doc, "표지 정보", size=9, color=FAINT, bold=True, ratio=1.2, space=4)
    _table(doc, ["항목", "내용"], [
        ["문서명", "취약점 진단 및 모의해킹 결과 보고서"],
        ["프로젝트", doc_meta["project"]],
        ["대상", " · ".join(f'{a["asset_id"]} {a["name"]}' for a in assets) or "[ ]"],
        ["작성", f'{doc_meta["written"]} (KST)'],
        ["작성 도구", doc_meta["tool"]],
        ["발견 건수", f"{len(items)}건 · 유형 {len(groups)}가지"],
        ["문서 버전", "[ ]"],
        ["보안 등급", "대외비 (팀 내부용)"],
    ], widths=[3.4, 12.0])


def build(doc_meta, items, path, owasp=()):
    """owasp 는 유형별 건수(화면 '점검 현황' 과 같은 집계). 없으면 그 그림만 빠진다."""
    doc = Document()
    _dress(doc)
    groups = _groups(items)                      # V-ID 는 문서 전체에서 한 번만 매긴다
    ranked = _ranked(groups)
    assets = _assets(items)
    counts = _counts(items)
    mine = {vid: [it for it in g] for vid, g in groups}

    _cover(doc, doc_meta, items, assets, groups)

    # ── 3 위험도 ──────────────────────────────────────
    doc.add_page_break()
    _head(doc, "3  위험도 평가 기준 및 적용 결과", 2)
    _head(doc, "3-2. 위험도 적용 결과", 3)
    for a in assets:
        _say(doc, f'[{a["zone"]}] {a["asset_id"]} {a["name"]} ({a["url"]})', size=10, bold=True, space=4)
        here = [(vid, [i for i in g if i["target_id"] == a["target_id"]]) for vid, g in ranked]
        here = [(vid, g) for vid, g in here if g]
        _table(doc, ["V-ID", "취약점 유형", "항목 코드", "건수", "CVSS (최고)", "위험도"],
               [[vid, g[0]["module_name"], g[0]["kisa"] or "[ ]", f"{len(g)}건", _top_cvss(g),
                 g[0]["top_severity"]] for vid, g in here]
               or [["-", "발견한 취약점 없음", "-", "0건", "-", "-"]],
               widths=[1.5, 4.6, 3.4, 1.4, 2.3, 2.2])
    _say(doc, "CVSS 에 (제안) 이 붙은 것은 모듈이 제안한 값입니다. 화면에서 벡터를 확정하면 떨어집니다.",
         size=8.5, color=FAINT, ratio=1.25, space=10)

    # ── 4 요약 ────────────────────────────────────────
    doc.add_page_break()
    _head(doc, "4  진단 결과 요약", 2)
    _head(doc, "4-1. 총평", 3)
    hit = sum(1 for a in assets if a["items"])
    _cards(doc, [(f"{len(groups)}개 · {len(items)}건", "취약점 · 건 (V-xx · V-xx-n)"),
                 (f'{counts["Critical"]}건', "Critical"),
                 (f'{counts["High"]}건', "High"),
                 (f"{hit} / {len(assets)}곳", "취약점이 나온 대상")])
    _callout(doc, _overall(items, assets, groups))
    # 그림은 쪽 너비를 다 쓴다. 둘을 나란히 두면 구간이 반으로 좁아져 숫자가 겹치거나
    # 잘린다(11-22 사용자 지적) — 세로로 쌓고 각자 넓게 그린다
    report_chart.place(doc, _sev_chart(counts), 15.4, 5.6)
    chart = _asset_chart(assets)
    if chart:
        report_chart.place(doc, chart, 15.4, max(4.4, 2.2 + 1.1 * hit))
    _say(doc, "● 건수는 건 단위(V-xx-n) 기준입니다. 오탐으로 내린 것은 빠져 있고, "
              "일부러 심어 둔 취약점이 몇 건인지는 사람이 가려 적습니다. "
              "구간이 좁아 숫자가 안 들어가는 자리는 비워 두었습니다 — 그 숫자는 아래 4-2 표에 있습니다.",
         size=8.5, color=FAINT, ratio=1.25, space=10)
    chart = _owasp_chart(owasp)
    if chart:
        tall = max(4.6, 2.2 + 1.0 * len([r for r in owasp if r["total"]]))
        report_chart.place(doc, chart, 15.4, tall)
        _say(doc, "● 결과 하나는 그 결과를 낸 모듈의 첫 점검 항목 코드로 한 번만 셉니다 — "
                  "합이 위 건수와 맞습니다. 좁은 구간은 숫자를 비워 두었습니다.",
             size=8.5, color=FAINT, ratio=1.25, space=10)

    _head(doc, "4-2. 대상별 취약점 요약", 3)
    _say(doc, "구역 · 대상별 위험도 건수와 전체 취약점 목록입니다.", size=10, space=6)
    rows, strong, zone_now, sub = [], [], None, None
    for a in assets:
        c = _counts(a["items"])
        if zone_now is not None and a["zone"] != zone_now:
            rows.append([f"{zone_now} 소계", "", ""] + [sub[k] for k in LABELS] + [sum(sub.values())])
            strong.append(len(rows) - 1)
            sub = None
        if sub is None or a["zone"] != zone_now:
            sub = {k: 0 for k in LABELS}
        zone_now = a["zone"]
        for k in LABELS:
            sub[k] += c[k]
        rows.append([a["zone"], a["asset_id"], a["name"]] + [c[k] for k in LABELS] + [len(a["items"])])
    if sub is not None:
        rows.append([f"{zone_now} 소계", "", ""] + [sub[k] for k in LABELS] + [sum(sub.values())])
        strong.append(len(rows) - 1)
    rows.append(["합계", "", ""] + [counts[k] for k in LABELS] + [len(items)])
    strong.append(len(rows) - 1)
    _table(doc, ["구역", "자산 ID", "대상", "■ Critical", "■ High", "■ Medium", "■ Low", "■ Info", "합계"],
           rows, head_colors={f"■ {k}": v for k, v in SEV_COLOR.items()}, strong=strong,
           widths=[2.0, 1.3, 3.0, 1.8, 1.6, 2.0, 1.3, 1.3, 1.1], head_size=7.5)
    _bar(doc, counts)
    _say(doc, "※ 건수는 건 단위(V-xx-n) 기준입니다.", size=8.5, color=FAINT, ratio=1.25, space=10)

    _say(doc, "취약점 목록:", size=10, space=4)
    _table(doc, ["V-ID", "취약점명", "취약점 유형(OWASP)", "대상", "건수", "위험도", "조치 구분"],
           [[vid, g[0]["module_name"], (g[0]["owasp"].split(" ")[0] if g[0]["owasp"] else "[ ]"),
             ", ".join(sorted({i["asset_id"] for i in g})), f"{len(g)}건", g[0]["top_severity"], "[ ]"]
            for vid, g in ranked], widths=[1.4, 4.4, 2.6, 2.0, 1.3, 1.8, 1.9])
    _say(doc, "※ 정렬: 위험도 높은 순(Critical → Info), 같은 위험도 안에서는 CVSS 점수가 높은 순",
         size=8.5, color=FAINT, ratio=1.25, space=2)
    _say(doc, "※ 취약점별 상세는 5장에 있습니다. 조치 구분(즉시/단기/중기)은 사람이 적습니다.",
         size=8.5, color=FAINT, ratio=1.25, space=10)

    # ── 5 Part A ─────────────────────────────────────
    doc.add_page_break()
    _head(doc, "5  Part A. 진단 상세 결과", 2)
    _bullet(doc, "서술 순서: 구역 → 대상 → 취약점 유형(V-xx) → 건(V-xx-n)")
    _bullet(doc, "유형 설명은 1회만 쓰고, 본문에는 대표 PoC 1~2건만 싣습니다")
    _head(doc, "5-1. 진단 방법", 3)
    _table(doc, ["구분", "담당 범위", "도구", "담당자"],
           [["자동 진단", "수집한 지점에 모듈을 돌린 결과", doc_meta["tool"], "[ ]"],
            ["수동 진단", "[ ]", "[ ]", "[ ]"]], widths=[2.0, 5.4, 5.0, 3.0])
    _say(doc, "※ 자동 진단 결과는 수동 재현으로 확인된 것만 건으로 등록합니다 — 아래 '상태' 가 확인됨인 것입니다.",
         size=8.5, color=FAINT, ratio=1.25, space=10)

    for n_a, a in enumerate(assets, 2):
        doc.add_page_break()
        _head(doc, f'5-{n_a}. [{a["zone"]}] 구역 — {a["asset_id"]} {a["name"]}', 3)
        _say(doc, a["url"], size=9, color=FAINT, ratio=1.25, space=6)
        here = [(vid, [i for i in mine[vid] if i["target_id"] == a["target_id"]]) for vid, _g in ranked]
        here = [(vid, g) for vid, g in here if g]
        if not here:
            _bullet(doc, "이 대상에서 발견한 취약점은 없습니다")
            continue
        for n, (vid, g) in enumerate(here, 1):
            if n > 1:
                doc.add_page_break()
            _detail(doc, vid, g)

    doc.save(path)
    return doc


def _detail(doc, vid, g):
    """취약점 유형 하나 — 개요 표, 건별 목록, 대표 PoC."""
    _head(doc, f'{vid}. {g[0]["module_name"]}', 4)
    _table(doc, ["항목", "내용"], [
        ["위험도", f'{g[0]["top_severity"]} (건 중 최고, CVSS {_top_cvss(g)})'],
        ["CVSS Vector", g[0]["cvss_vector"] or "[ ]"],
        ["항목 코드 / CWE", f'{g[0]["kisa"] or "[ ]"} / [ ]'],
        ["OWASP 2025", g[0]["owasp"] or "[ ]"],
        ["건수", f"{len(g)}건"],
        ["발견 방법", f'자동(딸깍이 — {g[0]["module_name"]})'],
        ["보안 대책", "7-3 참조 — " + (g[0]["recommendation"] or "[ ]").split(".")[0][:80]],
    ], widths=[3.4, 12.0])
    _bullet(doc, "설명: " + (g[0]["module_desc"] or "")[:400])
    _hole(doc, "위험 평가 설명: [악용 전제 조건과 난이도, 등급 산정 근거]")
    _hole(doc, "영향: [기밀성 · 무결성 · 가용성 · 금전 · 평판 · 규제 중 해당하는 것]")

    _say(doc, "건별 목록:", size=10, space=4)
    _table(doc, ["건 ID", "위치 (URL · 파라미터)", "메서드", "위험도", "의도적", "시나리오 사용",
                 "탐지 검증", "증거", "상태"],
           [[f"{vid}-{k}", "`" + it["location"] + "`", it["method"], it["severity_label"],
             "[ ]", "[ ]", "[ ]", ("요청·응답 수록" if it["request"] else "근거만"), it["status_label"]]
            for k, it in enumerate(g, 1)],
           widths=[1.4, 4.2, 1.3, 1.5, 1.1, 1.5, 1.3, 1.8, 1.3], head_size=8)

    rep = next((i for i in g if i["request"]), g[0])
    _say(doc, f'대표 PoC ({vid}-{g.index(rep) + 1}): {rep["title"]}', size=10, space=4)
    _hole(doc, "재현 단계: [1. 2. 3. 사람이 적습니다]")
    _code(doc, rep["evidence"], "근거")
    if rep["request"]:
        _code(doc, rep["request"], "요청 발췌")
        _code(doc, rep["response"], "응답 발췌")
    _say(doc, "조치방안: " + (rep["recommendation"] or "[ ]"), size=10, space=10)
