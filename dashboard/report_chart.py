"""보고서에 넣을 막대 그림 — Word 가 차트로 읽는 OOXML 을 직접 쓴다.

왜 이렇게 하나. EC2-4 에는 matplotlib 도 한글 글꼴도 없다. 그림 파일을 만들어 넣으면
축 이름이 네모로 나오고, 확대하면 깨지고, Word 에서 색 하나 못 고친다. 차트 부품
(`/word/charts/chartN.xml`)을 직접 써 넣으면 글꼴은 문서 글꼴을 따르고, 벡터로 인쇄되고,
사람이 Word 에서 바로 손볼 수 있다. 데이터 원본(엑셀)은 넣지 않아 '데이터 편집' 은 안 된다 —
숫자를 고칠 일이 있으면 딸깍이에서 다시 내려받는다.

팀 보고서 생성 도구(`SaeMoi/auto_report` 의 `render/chart.py`)가 같은 방식을 쓴다. 최종
결과보고서 4-1 의 두 그림(위험도별 건수 · 대상별 위험도 분포)이 그렇게 그려져 있어서,
딸깍이가 내는 그림도 그 자리에 그대로 들어갈 수 있게 맞췄다.
"""
import math

from docx.opc.packuri import PackURI
from docx.opc.part import Part
from docx.oxml import parse_xml

CT = "application/vnd.openxmlformats-officedocument.drawingml.chart+xml"
RT = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart"
NS_C = "http://schemas.openxmlformats.org/drawingml/2006/chart"
NS_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

FONT = "Noto Sans KR"
GRID = "E6E3DC"      # 격자선 — 표 가로줄보다 한 단계 옅게
AXIS = "BFBBB2"      # 축선
LABEL = "55534E"     # 축 글자(본문 보조색)
EMU_CM = 360000


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _text(size=800, color=LABEL, bold=False):
    """축·범례 글자 모양. 한글이라 latin 과 ea 를 같이 적는다."""
    return (f'<c:txPr><a:bodyPr/><a:lstStyle/><a:p><a:pPr><a:defRPr sz="{size}" b="{int(bold)}">'
            f'<a:solidFill><a:srgbClr val="{color}"/></a:solidFill>'
            f'<a:latin typeface="{FONT}"/><a:ea typeface="{FONT}"/></a:defRPr></a:pPr>'
            f'<a:endParaRPr lang="ko-KR"/></a:p></c:txPr>')


def _title(text):
    return (f'<c:title><c:tx><c:rich><a:bodyPr/><a:lstStyle/><a:p><a:pPr><a:defRPr sz="900" b="1">'
            f'<a:solidFill><a:srgbClr val="{LABEL}"/></a:solidFill>'
            f'<a:latin typeface="{FONT}"/><a:ea typeface="{FONT}"/></a:defRPr></a:pPr>'
            f'<a:r><a:rPr lang="ko-KR"/><a:t>{_esc(text)}</a:t></a:r></a:p></c:rich></c:tx>'
            f'<c:overlay val="0"/></c:title><c:autoTitleDeleted val="0"/>')


def _labels(inside, color, hide=()):
    """막대 값 라벨. 0 은 적지 않는다(서식 '0;-0;;') — 0 을 적으면 축이 지저분해진다."""
    pos = '<c:dLblPos val="ctr"/>' if inside else '<c:dLblPos val="outEnd"/>'
    # 구간이 숫자보다 좁으면 그 자리만 숫자를 지운다 — 두면 옆 숫자와 겹치거나 잘린다
    drop = "".join(f'<c:dLbl><c:idx val="{i}"/><c:delete val="1"/></c:dLbl>' for i in sorted(hide))
    return ('<c:dLbls>' + drop + '<c:numFmt formatCode="0;-0;;" sourceLinked="0"/><c:spPr><a:noFill/></c:spPr>'
            + _text(750, color, bold=True) + pos
            + '<c:showLegendKey val="0"/><c:showVal val="1"/><c:showCatName val="0"/>'
              '<c:showSerName val="0"/><c:showPercent val="0"/><c:showBubbleSize val="0"/></c:dLbls>')


def _series(idx, name, values, color, colors=None, inside=False, label_color="FFFFFF", hide=()):
    out = [f'<c:ser><c:idx val="{idx}"/><c:order val="{idx}"/>']
    if name:
        out.append(f'<c:tx><c:strRef><c:f>s{idx}</c:f><c:strCache><c:ptCount val="1"/>'
                   f'<c:pt idx="0"><c:v>{_esc(name)}</c:v></c:pt></c:strCache></c:strRef></c:tx>')
    out.append(f'<c:spPr><a:solidFill><a:srgbClr val="{color}"/></a:solidFill><a:ln><a:noFill/></a:ln></c:spPr>')
    out.append('<c:invertIfNegative val="0"/>')
    for i, one in enumerate(colors or []):               # 막대마다 색이 다른 그림(위험도별 건수)
        out.append(f'<c:dPt><c:idx val="{i}"/><c:invertIfNegative val="0"/><c:bubble3D val="0"/>'
                   f'<c:spPr><a:solidFill><a:srgbClr val="{one}"/></a:solidFill>'
                   f'<a:ln><a:noFill/></a:ln></c:spPr></c:dPt>')
    out.append(_labels(inside, label_color, hide))
    return out


def _cat_val(categories, values):
    cats = "".join(f'<c:pt idx="{i}"><c:v>{_esc(c)}</c:v></c:pt>' for i, c in enumerate(categories))
    vals = "".join(f'<c:pt idx="{i}"><c:v>{v}</c:v></c:pt>' for i, v in enumerate(values))
    return (f'<c:cat><c:strLit><c:ptCount val="{len(categories)}"/>{cats}</c:strLit></c:cat>'
            f'<c:val><c:numLit><c:formatCode>General</c:formatCode>'
            f'<c:ptCount val="{len(values)}"/>{vals}</c:numLit></c:val></c:ser>')


def _axes(cat_id, val_id, horizontal, major=None, max_val=None):
    """세로 막대면 분류축이 아래(b), 가로 막대면 왼쪽(l). 격자선은 값축에만 둔다."""
    cat_pos, val_pos = ("l", "b") if horizontal else ("b", "l")
    # 가로 막대는 분류축을 뒤집어야 첫 줄이 맨 위로 온다
    order = "maxMin" if horizontal else "minMax"
    scaling = f'<c:scaling><c:orientation val="{order}"/></c:scaling>'
    line = f'<c:spPr><a:ln w="9525"><a:solidFill><a:srgbClr val="{AXIS}"/></a:solidFill></a:ln></c:spPr>'
    cat_ax = (f'<c:catAx><c:axId val="{cat_id}"/>{scaling}<c:delete val="0"/>'
              f'<c:axPos val="{cat_pos}"/><c:numFmt formatCode="General" sourceLinked="0"/>'
              f'<c:majorTickMark val="none"/><c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/>'
              f'{line}{_text()}<c:crossAx val="{val_id}"/><c:crosses val="autoZero"/>'
              f'<c:auto val="1"/><c:lblAlgn val="ctr"/><c:lblOffset val="100"/>'
              f'<c:tickLblSkip val="1"/><c:tickMarkSkip val="1"/>'
              f'<c:noMultiLvlLbl val="0"/></c:catAx>')
    grid = (f'<c:majorGridlines><c:spPr><a:ln w="9525"><a:solidFill>'
            f'<a:srgbClr val="{GRID}"/></a:solidFill></a:ln></c:spPr></c:majorGridlines>')
    unit = f'<c:majorUnit val="{major}"/>' if major else ""
    val_ax = (f'<c:valAx><c:axId val="{val_id}"/><c:scaling><c:orientation val="minMax"/>'
              + (f'<c:max val="{max_val}"/>' if max_val else "")
              + f'</c:scaling><c:delete val="0"/><c:axPos val="{val_pos}"/>{grid}'
              f'<c:numFmt formatCode="General" sourceLinked="0"/>'
              f'<c:majorTickMark val="none"/><c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/>'
              f'{line}{_text()}<c:crossAx val="{cat_id}"/>'
              # 가로 막대는 분류축을 뒤집었으므로(첫 줄이 위) 값축을 반대 끝에 둬야 아래로 온다
              + (f'<c:crosses val="{"max" if horizontal else "autoZero"}"/>')
              + f'<c:crossBetween val="between"/>{unit}</c:valAx>')
    return cat_ax + val_ax


def chart_xml(spec):
    """그림 하나를 OOXML 로. spec 은 아래 `column`·`stacked` 가 만들어 준다."""
    horizontal = spec.get("dir") == "bar"
    cat_id, val_id = 111111111, 222222222
    sers = []
    for i, s in enumerate(spec["series"]):
        sers += _series(i, s.get("name", ""), s["values"], s.get("color", "2F5B63"),
                        s.get("colors"), inside=spec.get("inside", False),
                        label_color=s.get("label_color", "FFFFFF"), hide=s.get("hide", ()))
        sers.append(_cat_val(spec["categories"], s["values"]))
    stacked = spec.get("grouping") == "stacked"
    legend = ('<c:legend><c:legendPos val="b"/><c:overlay val="0"/>' + _text(750) + "</c:legend>"
              if spec.get("legend") else "")
    body = (f'<c:barChart><c:barDir val="{"bar" if horizontal else "col"}"/>'
            f'<c:grouping val="{"stacked" if stacked else "clustered"}"/><c:varyColors val="0"/>'
            + "".join(sers)
            + f'<c:gapWidth val="{spec.get("gap", 60)}"/>'
            + (f'<c:overlap val="{100 if stacked else -10}"/>')
            + f'<c:axId val="{cat_id}"/><c:axId val="{val_id}"/></c:barChart>')
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<c:chartSpace xmlns:c="{NS_C}" xmlns:a="{NS_A}" xmlns:r="{NS_R}">'
            f'<c:chart>{_title(spec["title"])}<c:plotArea><c:layout/>{body}'
            + _axes(cat_id, val_id, horizontal, spec.get("major"), spec.get("max"))
            + f'<c:spPr><a:noFill/><a:ln><a:noFill/></a:ln></c:spPr></c:plotArea>{legend}'
            f'<c:plotVisOnly val="1"/><c:dispBlanksAs val="gap"/></c:chart>'
            f'<c:spPr><a:noFill/><a:ln><a:noFill/></a:ln></c:spPr>{_text()}</c:chartSpace>')


def _add_part(doc, xml):
    """차트 부품을 문서에 붙이고 관계 id 를 돌려준다."""
    main = doc.part
    n = 1 + sum(1 for p in main.package.iter_parts() if str(p.partname).startswith("/word/charts/chart"))
    part = Part(PackURI(f"/word/charts/chart{n}.xml"), CT, xml.encode("utf-8"), main.package)
    return main.relate_to(part, RT), n


def place(doc, spec, width_cm, height_cm, par=None):
    """문단 하나에 그림 하나를 앉힌다. par 를 주면 그 문단에(표 칸 안에) 넣는다."""
    rid, n = _add_part(doc, chart_xml(spec))
    cx, cy = int(width_cm * EMU_CM), int(height_cm * EMU_CM)
    par = par if par is not None else doc.add_paragraph()
    run = par.add_run()
    run._r.append(parse_xml(
        f'<w:drawing xmlns:w="{NS_W}" xmlns:wp="{NS_WP}" xmlns:a="{NS_A}" xmlns:c="{NS_C}" xmlns:r="{NS_R}">'
        f'<wp:inline distT="0" distB="0" distL="0" distR="0">'
        f'<wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="{1000 + n}" name="그림 {n}"/>'
        f'<wp:cNvGraphicFramePr/><a:graphic><a:graphicData uri="{NS_C}">'
        f'<c:chart r:id="{rid}"/></a:graphicData></a:graphic></wp:inline></w:drawing>'))
    return par


# ── 보고서가 쓰는 두 가지 ───────────────────────────────

def column(title, pairs, colors, major=None):
    """세로 막대 하나 — 막대마다 색이 다르다(위험도별 건수)."""
    return {"title": title, "categories": [k for k, _n in pairs], "dir": "col", "legend": False,
            "major": major, "series": [{"values": [n for _k, n in pairs], "color": colors[0],
                                        "colors": colors, "label_color": LABEL}]}


# 라벨 한 글자가 차지하는 폭(cm). 7.5pt 숫자 기준으로 재어 둔 값이다
DIGIT_CM = 0.17


def axis_top(top):
    """Word 가 잡을 축 끝을 미리 센다 — 1·2·2.5·5 꼴로 올려 잡는다.

    줄 합이 174 면 축은 200 까지 간다. 174 로 재면 구간이 실제보다 넓게 잡혀,
    숫자가 안 들어가는 자리를 들어간다고 잘못 본다.
    """
    if top <= 0:
        return 1
    step = 10 ** math.floor(math.log10(top))
    for m in (1, 2, 2.5, 5):
        if top <= step * m:
            return step * m
    return step * 10


def stacked(title, categories, series, legend=True, width_cm=15.4):
    """가로 누적 막대 — 줄 하나가 대상(또는 유형), 구간이 위험도.

    구간 안에 숫자를 적는데, 1~2건짜리 구간은 숫자보다 좁아 옆 숫자와 겹치거나 잘린다
    (11-22 사용자 지적). 그래서 **그 구간에 숫자가 들어가는지 먼저 재고** 안 들어가면
    그 자리만 숫자를 뺀다. 그림을 키우면 들어가는 자리가 늘어난다.
    """
    rows = [sum(s["values"][i] for s in series) for i in range(len(categories))]
    top = axis_top(max(rows + [1]))
    plot = max(2.0, width_cm * 0.72)                       # 줄 이름·여백을 뺀 실제 막대 자리
    out = []
    for s in series:
        hide = [i for i, v in enumerate(s["values"])
                if v and v / top * plot < DIGIT_CM * len(str(v)) + 0.1]
        out.append({**s, "hide": hide})
    return {"title": title, "categories": categories, "dir": "bar", "grouping": "stacked",
            "legend": legend, "inside": True, "gap": 70, "series": out}
