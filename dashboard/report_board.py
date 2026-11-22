"""공격 체인 다이어그램 — 수사보드를 Word **도형**으로 그린다(결과보고서 양식 그림 6-1).

왜 그림 파일이 아닌가. 차트와 같은 까닭이다(`report_chart.py` 머리말) — EC2-4 에 한글 글꼴이
없고, 그림 파일은 확대하면 깨지고 사람이 못 고친다. 도형으로 넣으면 Word 에서 카드를 끌어
옮기고 글자를 고칠 수 있다.

**보드 자리를 그대로 쓰지 않는다.** 화면 보드는 가로 5000px 를 넘어 A4 에 넣으면 카드가
0.6cm 가 되어 못 읽는다. 보고서에서는 다시 앉힌다.

    · 줄 = 전술(ATT&CK 순서). 칸 = 그 전술 안의 카드, 보드의 왼쪽→오른쪽 차례
    · 같은 제목의 결과 여럿은 **한 장으로 접는다**('민감 파일 노출 7건'). 접힌 건 ID 는 다 적는다
    · 선은 접힌 뒤의 카드끼리 다시 잇는다. 같은 두 장을 잇는 선이 여럿이면 하나로

양식의 그림 6-1 이 요구하는 것이 '자산 ID 와 건 ID 를 화살표로 연결' 이라, 카드 밑줄에
건 ID(V-xx-n)를 적는다.
"""
import re

from docx.oxml import parse_xml

from .attack import TACTIC_NAME, TACTIC_ORDER

A = "http://schemas.openxmlformats.org/drawingml/2006/main"
WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
WPG = "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
WPS = "http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
EMU = 360000                      # 1cm

FONT = "Noto Sans KR"
# 카드는 하얗게 두고 **색은 점과 선에만** 쓴다(11-22 사용자 레퍼런스). 바탕을 칠하면
# 카드가 커 보여 선이 묻힌다. 종류마다 (점·선 색, 테두리).
RULE = "D9D6CE"                   # 표의 가로줄과 같은 색 — 카드 테두리도 이것 하나로
SKIN = {
    "observed": ("8A877F", RULE),          # 읽어 낸 것
    "cve": ("9C3E39", RULE),               # CVE
    "finding": ("A88B35", RULE),           # 점검 결과
    "goal": ("5E7C5A", RULE),              # 목표
}
PAPER = "FFFFFF"
WIRE = "B9B6AE"
LABEL = "55534E"
FAINT = "8A877F"

CARD_H = 1.75
SLOT = 2.15                       # 카드 한 장이 차지하는 세로 자리
HEAD_H = 0.65                     # 열 머리(전술 이름) 높이


def _esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _short(text):
    """카드 밑줄에 주소를 적을 때는 호스트를 떼어 낸다 — 줄 안에 안 들어간다."""
    text = str(text or "").strip()
    m = re.match(r"https?://[^/]+(/.*)", text)
    return m.group(1) if m else text


def _cut(text, n):
    text = str(text or "").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _para(text, size, color, bold=False):
    return (f'<w:p><w:pPr><w:spacing w:after="0" w:line="216" w:lineRule="auto"/></w:pPr>'
            f'<w:r><w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}" w:eastAsia="{FONT}"/>'
            f'{"<w:b/>" if bold else ""}<w:color w:val="{color}"/><w:sz w:val="{int(size * 2)}"/>'
            f'</w:rPr><w:t xml:space="preserve">{_esc(text)}</w:t></w:r></w:p>')


def _dot(color, size=6):
    """제목 앞의 색 점 — 종류를 한눈에. 도형을 하나 더 두지 않고 글자로 찍는다."""
    return (f'<w:r><w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}" w:eastAsia="{FONT}"/>'
            f'<w:color w:val="{color}"/><w:sz w:val="{int(size * 2)}"/></w:rPr>'
            f'<w:t xml:space="preserve">● </w:t></w:r>')


def _card(i, x, y, w, h, kind, title, sub, mark=""):
    tone, line = SKIN.get(kind, SKIN["finding"])
    body = ('<w:p><w:pPr><w:spacing w:after="0" w:line="216" w:lineRule="auto"/></w:pPr>'
            + _dot(tone)
            + f'<w:r><w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}" w:eastAsia="{FONT}"/>'
            f'<w:b/><w:color w:val="1C1C1C"/><w:sz w:val="13"/></w:rPr>'
            f'<w:t xml:space="preserve">{_esc(title)}</w:t></w:r></w:p>')
    if sub:
        body += _para(sub, 5.5, LABEL)
    if mark:                                   # 상태 칩 — 확인이 아닌 단계만
        body += ('<w:p><w:pPr><w:spacing w:after="0" w:line="200" w:lineRule="auto"/></w:pPr>'
                 + _dot(tone, 5)
                 + f'<w:r><w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}" w:eastAsia="{FONT}"/>'
                 f'<w:color w:val="{tone}"/><w:sz w:val="11"/></w:rPr>'
                 f'<w:t xml:space="preserve">{_esc(mark)}</w:t></w:r></w:p>')
    return (f'<wps:wsp><wps:cNvPr id="{200 + i}" name="카드 {i}"/><wps:cNvSpPr txBox="1"/><wps:spPr>'
            f'<a:xfrm><a:off x="{int(x * EMU)}" y="{int(y * EMU)}"/>'
            f'<a:ext cx="{int(w * EMU)}" cy="{int(h * EMU)}"/></a:xfrm>'
            f'<a:prstGeom prst="roundRect"><a:avLst><a:gd name="adj" fmla="val 9000"/></a:avLst></a:prstGeom>'
            f'<a:solidFill><a:srgbClr val="{PAPER}"/></a:solidFill>'
            f'<a:ln w="9525"><a:solidFill><a:srgbClr val="{line}"/></a:solidFill></a:ln></wps:spPr>'
            f'<wps:txbx><w:txbxContent xmlns:w="{W}">{body}</w:txbxContent></wps:txbx>'
            f'<wps:bodyPr rot="0" vert="horz" wrap="square" lIns="45000" tIns="27000" rIns="36000" '
            f'bIns="18000" anchor="ctr"><a:noAutofit/></wps:bodyPr></wps:wsp>')


def _name(i, x, w, text):
    """열 머리의 전술 이름 — 보드의 띠 이름과 같은 자리."""
    return (f'<wps:wsp><wps:cNvPr id="{600 + i}" name="전술 {i}"/><wps:cNvSpPr txBox="1"/><wps:spPr>'
            f'<a:xfrm><a:off x="{int(x * EMU)}" y="0"/>'
            f'<a:ext cx="{int(w * EMU)}" cy="{int(HEAD_H * EMU)}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></wps:spPr>'
            f'<wps:txbx><w:txbxContent xmlns:w="{W}">{_para(text, 6.5, LABEL, bold=True)}</w:txbxContent></wps:txbx>'
            f'<wps:bodyPr wrap="square" lIns="45000" tIns="0" rIns="0" bIns="0" anchor="b">'
            f'<a:noAutofit/></wps:bodyPr></wps:wsp>')


def _wire(i, x1, y1, x2, y2, color=WIRE, sideways=True):
    """선 하나 — **한 번만 휘는 곡선**. 가로로 나가 가로로 들어온다.

    Word 가 주는 곡선 커넥터(curvedConnector3)는 높이 차가 작으면 S 자로 꿈틀거려
    지렁이처럼 보인다(11-22 사용자 지적). 그래서 길을 직접 그린다 — 양 끝의 손잡이를
    한 방향으로만 내밀어 베지에 하나로 잇는다. 그러면 나가는 쪽도 들어오는 쪽도 카드
    옆구리와 수평(또는 수직)이고, 가운데만 부드럽게 넘어간다.

    sideways 가 거짓이면 세로로 잇는다 — 같은 열 안의 두 카드다. 옆구리끼리 이으면 선이
    뒤로 돌아 나가면서 카드를 가로지른다(11-22 사용자 지적).

    굵기와 색은 표의 가로줄과 같은 말을 쓴다 — 가늘게(0.75pt), 한 가지 색. 색은 점에만.
    """
    # 뒤집기(flipH/flipV)를 쓰지 않는다 — 길까지 같이 뒤집혀 화살촉이 반대쪽에 붙는다.
    # 자리를 길 안에 그대로 적고, 손잡이만 방향에 맞춰 내민다.
    ox, oy = min(x1, x2), min(y1, y2)
    w = max(1, int(abs(x2 - x1) * EMU))
    h = max(1, int(abs(y2 - y1) * EMU))
    p1 = (int((x1 - ox) * EMU), int((y1 - oy) * EMU))
    p2 = (int((x2 - ox) * EMU), int((y2 - oy) * EMU))
    if sideways:                               # 가로로 나가 가로로 들어온다(열이 다를 때)
        bend = max(int(w * 0.52), 160000)   # 적어도 0.44cm 는 가로로 나가게
        way = 1 if x2 >= x1 else -1
        c1 = (p1[0] + way * bend, p1[1])
        c2 = (p2[0] - way * bend, p2[1])
    else:                                      # 같은 열이면 세로로 — 아래로 나가 위로 들어온다
        bend = max(int(h * 0.5), 120000)
        way = 1 if y2 >= y1 else -1
        c1 = (p1[0], p1[1] + way * bend)
        c2 = (p2[0], p2[1] - way * bend)
    path = (f'<a:path w="{w}" h="{h}">'
            f'<a:moveTo><a:pt x="{p1[0]}" y="{p1[1]}"/></a:moveTo>'
            f'<a:cubicBezTo><a:pt x="{c1[0]}" y="{c1[1]}"/><a:pt x="{c2[0]}" y="{c2[1]}"/>'
            f'<a:pt x="{p2[0]}" y="{p2[1]}"/></a:cubicBezTo></a:path>')
    return (f'<wps:wsp><wps:cNvPr id="{800 + i}" name="선 {i}"/><wps:cNvSpPr/><wps:spPr>'
            f'<a:xfrm><a:off x="{int(ox * EMU)}" y="{int(oy * EMU)}"/>'
            f'<a:ext cx="{w}" cy="{h}"/></a:xfrm>'
            f'<a:custGeom><a:avLst/><a:gdLst/><a:ahLst/><a:cxnLst/>'
            f'<a:rect l="0" t="0" r="r" b="b"/><a:pathLst>{path}</a:pathLst></a:custGeom>'
            f'<a:noFill/>'
            f'<a:ln w="9525" cap="rnd"><a:solidFill><a:srgbClr val="{color}"/></a:solidFill>'
            f'<a:round/><a:tailEnd type="triangle" w="sm" len="sm"/></a:ln></wps:spPr>'
            f'<wps:bodyPr/></wps:wsp>')


# ── 보고서용으로 다시 앉히기 ────────────────────────────

def _fold_key(n):
    """같은 제목의 결과를 한 장으로 접기 위한 열쇠. 괄호·콜론 앞까지가 '같은 제목' 이다."""
    if n["kind"] != "finding":
        return ("one", n["id"])
    head = re.split(r"[(:]", n["title"])[0].strip()
    return ("fold", n["tactic"], head)


def lay_out(nodes, edges, vid_of, width_cm=25.0):
    """카드와 선의 자리를 잡는다 — **열이 왼쪽에서 오른쪽으로 흐르는** 모양(11-22 사용자 레퍼런스).

    보드와 같은 짜임이다. 열 하나가 전술 하나이고, 카드는 그 열 안에서 위아래로 선다.
    세로로 쌓던 전판은 카드가 2.4cm 밖에 안 돼 제목이 잘렸다 — 이 그림은 가로 쪽에 싣는다.

    자리를 정하는 순서
      ① 같은 제목의 결과를 한 장으로 접는다
      ② 전술 차례대로 열을 세운다
      ③ 열 안의 차례는 **들어오는 선의 평균 높이**로 정한다(부모 옆에 자식이 서게). 두 번 쓸어
         내리면 선이 거의 안 꼬인다
      ④ 열마다 가운데에 맞춰 띄운다 — 레퍼런스처럼 가운데로 모이는 모양

    vid_of 는 결과 id → 'V-xx-n' 를 돌려주는 함수.
    """
    seen, cards = {}, []
    for n in sorted(nodes, key=lambda n: (TACTIC_ORDER.get(n["tactic"], 99), n["x"], n["y"])):
        key = _fold_key(n)
        if key in seen:
            cards[seen[key]]["ids"].append(n["id"])
            continue
        seen[key] = len(cards)
        cards.append({"ids": [n["id"]], "kind": n["kind"], "tactic": n["tactic"],
                      "title": re.split(r"[(:]", n["title"])[0].strip() if n["kind"] == "finding"
                      else n["title"], "sub": n["sub"], "status": n["status"]})
    at = {nid: i for i, c in enumerate(cards) for nid in c["ids"]}

    links = set()
    for e in edges:
        a, b = at.get(e["src"]), at.get(e["dst"])
        if a is not None and b is not None and a != b:
            links.add((a, b))
    links = sorted(links)

    cols = []                                   # [(전술, [카드…]), …] 왼→오
    for c in cards:
        if not cols or cols[-1][0] != c["tactic"]:
            cols.append((c["tactic"], []))
        cols[-1][1].append(c)
    cols.sort(key=lambda r: TACTIC_ORDER.get(r[0], 99))
    col_of = {id(c): j for j, (_t, line) in enumerate(cols) for c in line}

    # ③ 들어오는 선의 평균 자리로 열 안 차례를 다시 매긴다
    rank = {id(c): i for _t, line in cols for i, c in enumerate(line)}
    parents = {}
    for a, b in links:
        parents.setdefault(id(cards[b]), []).append(cards[a])
    for _sweep in range(2):
        for _t, line in cols:
            line.sort(key=lambda c: (sum(rank[id(p)] for p in parents.get(id(c), []))
                                     / len(parents.get(id(c), [1])) if parents.get(id(c)) else
                                     rank[id(c)], rank[id(c)]))
            for i, c in enumerate(line):
                rank[id(c)] = i

    gut = 0.7                                   # 열 사이 틈 — 선이 지나갈 길
    card_w = max(2.3, (width_cm - gut * (len(cols) - 1)) / max(1, len(cols)))
    deep = max((len(line) for _t, line in cols), default=1)
    for j, (_t, line) in enumerate(cols):
        pad = (deep - len(line)) * SLOT / 2           # ④ 열을 가운데로
        for i, c in enumerate(line):
            c["x"] = j * (card_w + gut)
            c["y"] = HEAD_H + pad + i * SLOT
            c["w"] = card_w
    height = HEAD_H + deep * SLOT - (SLOT - CARD_H)

    for c in cards:
        vids = [v for v in (vid_of(i) for i in c["ids"]) if v]
        if c["kind"] == "finding":
            if len(c["ids"]) > 1:                    # 접은 장수는 제목에 — 밑줄은 건 ID 자리다
                c["title"] = f"{c['title']} {len(c['ids'])}건"
            c["sub"] = ", ".join(vids[:2]) + (f" 외 {len(vids) - 2}" if len(vids) > 2 else "")
        else:
            c["sub"] = _cut(_short(c["sub"]), 24)
        c["mark"] = c["status"] if c["status"] not in ("확인", "") else ""
    del col_of
    return cols, cards, links, height


def draw(doc, nodes, edges, vid_of, width_cm=25.0):
    """보드 한 판을 도형 묶음 하나로 그려 문단에 앉힌다. 그린 카드 목록을 돌려준다."""
    cols, cards, links, height = lay_out(nodes, edges, vid_of, width_cm)
    if not cards:
        return None, []
    shapes = []
    for i, (a, b) in enumerate(links):            # 선을 먼저 — 카드 뒤로 간다
        p, q = cards[a], cards[b]
        if q["x"] > p["x"] + 0.1:            # 오른쪽 옆구리 → 다음 카드 왼쪽 옆구리
            shapes.append(_wire(i, p["x"] + p["w"], p["y"] + CARD_H / 2,
                                q["x"], q["y"] + CARD_H / 2))
        elif q["y"] > p["y"]:                 # 같은 열(또는 되돌아가는 선)이면 아래로
            shapes.append(_wire(i, p["x"] + p["w"] / 2, p["y"] + CARD_H,
                                q["x"] + q["w"] / 2, q["y"], sideways=False))
        else:
            shapes.append(_wire(i, p["x"] + p["w"] / 2, p["y"],
                                q["x"] + q["w"] / 2, q["y"] + CARD_H, sideways=False))
    for j, (tac, line) in enumerate(cols):
        shapes.append(_name(j, line[0]["x"], line[0]["w"], TACTIC_NAME.get(tac, tac)))
        for c in line:
            shapes.append(_card(len(shapes), c["x"], c["y"], c["w"], CARD_H, c["kind"],
                                _cut(c["title"], 26), c["sub"], c.get("mark", "")))
    xml = (f'<w:drawing xmlns:w="{W}" xmlns:wp="{WP}" xmlns:a="{A}">'
           f'<wp:inline distT="0" distB="0" distL="0" distR="0">'
           f'<wp:extent cx="{int(width_cm * EMU)}" cy="{int(height * EMU)}"/>'
           f'<wp:docPr id="9100" name="공격 체인"/><wp:cNvGraphicFramePr/>'
           f'<a:graphic><a:graphicData uri="{WPG}"><wpg:wgp xmlns:wpg="{WPG}" xmlns:wps="{WPS}">'
           f'<wpg:cNvGrpSpPr/><wpg:grpSpPr><a:xfrm><a:off x="0" y="0"/>'
           f'<a:ext cx="{int(width_cm * EMU)}" cy="{int(height * EMU)}"/>'
           f'<a:chOff x="0" y="0"/><a:chExt cx="{int(width_cm * EMU)}" cy="{int(height * EMU)}"/>'
           f'</a:xfrm></wpg:grpSpPr>{"".join(shapes)}</wpg:wgp></a:graphicData></a:graphic>'
           f'</wp:inline></w:drawing>')
    par = doc.add_paragraph()
    par.add_run()._r.append(parse_xml(xml))
    return par, cards
