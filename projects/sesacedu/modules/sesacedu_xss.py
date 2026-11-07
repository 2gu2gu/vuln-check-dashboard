"""새싹에듀용 XSS 후보 탐색 모듈 — 반사형·저장형·DOM 기반.

테스트 값은 PortSwigger Web Security Academy XSS cheat sheet 를 참고해
서로 다른 태그와 이벤트 조합 100개로 구성했습니다.
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

이 프레임워크는 HTTP 요청·응답만 봅니다(브라우저를 실행하지 않습니다).
- 반사형: GET 쿼리에 값을 넣고 응답 본문에서 이벤트 속성 후보를 찾습니다.
- 저장형: 테스트 폼을 1회 제출하고 별도 GET 으로 저장된 표식을 확인합니다.
- DOM 기반: 페이지와 같은 출처 스크립트를 읽어 '소스→싱크' 패턴을 정적으로 찾습니다.
  실제 실행 여부(진짜 터지는지)는 세 모드 모두 브라우저로 별도 검증이 필요합니다.
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from dashboard import core, probe
from dashboard.core import Check


META = {
    "id": "sesacedu_xss_probe",
    "name": "새싹에듀 XSS 후보 탐색 (반사·저장·DOM)",
    "category": "입력 검증",
    "vuln": "XSS",
    "kind": "active",
    "stage": "probe",
    "roles": ["user_web", "admin_web", "practice"],
    "severity": "medium",
    "attack": [
        {"tactic": "TA0002", "technique": "T1059.007",
         "name": "Command and Scripting Interpreter: JavaScript"},
    ],
    "description": (
        "반사형은 GET 쿼리를 점검합니다. 저장형은 테스트 폼을 한 번 제출하고 별도 "
        "GET 으로 읽습니다. DOM 기반은 같은 출처 스크립트에서 소스→싱크 패턴을 정적으로 "
        "찾는 후보 탐지입니다. 실제 실행 여부는 모든 모드에서 별도 검증이 필요합니다."
    ),
    "params": [
        {"name": "mode", "need": "required", "type": "select", "default": "reflected",
         "label": "점검 모드", "options": [
             {"value": "reflected", "label": "반사형 (GET)"},
             {"value": "stored", "label": "저장형 (POST 폼 1회 + GET 조회)"},
             {"value": "dom", "label": "DOM 기반 (스크립트 소스→싱크 정적 분석)"},
         ]},
        {"name": "limit", "need": "optional", "type": "int", "default": "100",
         "label": "지점당 테스트 값 수",
         "help": "반사형 전용. 1~100 사이로 입력합니다. 최대값이면 지점 1개당 그만큼 요청합니다."},
        {"name": "read_path", "need": "conditional", "when": "저장형 모드(선택 입력)",
         "label": "조회 경로 (비우면 자동)", "default": "",
         "help": "비우면 저장 응답의 Location(새 글 주소)에서 자동으로 찾습니다. "
                 "자동으로 못 찾을 때만 같은 대상의 /경로 형식으로 입력하세요. 예: /test/posts/1"},
        {"name": "stored_vector", "need": "conditional", "when": "저장형 모드",
         "type": "int", "default": "1", "label": "저장할 테스트 값 번호",
         "help": "1~100 중 조합 하나만 저장합니다. 1번은 img/onerror입니다."},
        {"name": "write_ack", "need": "conditional", "when": "저장형 모드",
         "label": "저장 허용 확인", "default": "",
         "help": "삭제 가능한 테스트 데이터에서만 실행하고, 확인 칸에 WRITE를 입력하세요."},
        {"name": "dom_depth", "need": "conditional", "when": "DOM 기반 모드",
         "type": "int", "default": "20", "label": "읽을 외부 스크립트 수 (0~40)",
         "help": "페이지에 걸린 같은 출처 <script src> 를 앞에서부터 이만큼 읽습니다."},
    ],
}

HANDLER = "console.log('{T}')"

# ─────────── 테스트 값: 전부 사용자 조작(마우스·키보드) 없이 자동 실행 ───────────
# PortSwigger XSS cheat sheet 중 "fires without user interaction" 계열만 골랐습니다.
# 세 계열로 구성합니다:
#   ① 리소스 로드/에러 · SVG SMIL 애니메이션 · details[open] — 렌더 즉시 실행
#   ② autofocus → onfocus — 로드 직후 자동 포커스로 실행(클릭 불필요)
#   ③ CSS 애니메이션 onanimationstart — 요소가 그려지는 즉시 실행(<style> 포함)

_GIF = "data:image/gif;base64,R0lGODlhAQABAAAAACwAAAAAAQABAAA="  # 1x1 GIF → onload 자동
_KF = "vcdkf"  # CSS keyframes 이름(고정)
_STYLE = "<style>@keyframes %s{from{opacity:1}to{opacity:.99}}</style>" % _KF

# ① 렌더 즉시 자동 실행 (수동 조작 없음). 첫 번째는 저장형 기본값인 img/onerror.
AUTO_SPECIAL = (
    ("img", "onerror", '<img src="data:," onerror="{H}">'),
    ("img", "onload", f'<img src="{_GIF}" onload="{{H}}">'),
    ("svg", "onload", '<svg onload="{H}"></svg>'),
    ("iframe", "onload", '<iframe src="about:blank" onload="{H}"></iframe>'),
    ("body", "onload", '<body onload="{H}">'),
    ("body", "onpageshow", '<body onpageshow="{H}">'),
    ("script", "onerror", '<script src="/vcd-nonexistent.js" onerror="{H}"></script>'),
    ("link", "onerror", '<link rel="stylesheet" href="/vcd-nonexistent.css" onerror="{H}">'),
    ("link", "onload", '<link rel="stylesheet" href="data:text/css," onload="{H}">'),
    ("object", "onerror", '<object data="/vcd-nonexistent" onerror="{H}"></object>'),
    ("input", "onerror", '<input type="image" src="data:," onerror="{H}">'),
    ("video", "onerror", '<video src="data:," onerror="{H}"></video>'),
    ("video", "onloadstart", '<video src="data:video/mp4," onloadstart="{H}"></video>'),
    ("audio", "onerror", '<audio src="data:," onerror="{H}"></audio>'),
    ("audio", "onloadstart", '<audio src="data:audio/mpeg," onloadstart="{H}"></audio>'),
    ("details", "ontoggle", '<details open ontoggle="{H}"><summary>x</summary></details>'),
    ("animate", "onbegin", '<svg><rect width="5" height="5"><animate attributeName="x" from="0" to="1" dur="1s" onbegin="{H}"/></rect></svg>'),
    ("animate", "onend", '<svg><rect width="5" height="5"><animate attributeName="x" from="0" to="1" dur="0.2s" onend="{H}"/></rect></svg>'),
    ("animate", "onrepeat", '<svg><rect width="5" height="5"><animate attributeName="x" from="0" to="1" dur="0.2s" repeatCount="2" onrepeat="{H}"/></rect></svg>'),
    ("set", "onbegin", '<svg><set attributeName="x" to="1" dur="1s" onbegin="{H}"/></svg>'),
    ("set", "onend", '<svg><set attributeName="x" to="1" dur="0.2s" onend="{H}"/></svg>'),
    ("animatetransform", "onbegin", '<svg><rect><animateTransform attributeName="transform" type="scale" from="1" to="2" dur="1s" onbegin="{H}"/></rect></svg>'),
    ("animatemotion", "onbegin", '<svg><rect><animateMotion dur="1s" onbegin="{H}"/></rect></svg>'),
)

# ② autofocus 가 로드 직후 포커스를 줘서 onfocus 가 조작 없이 실행된다.
FOCUS_CONTROL_TEMPLATES = {
    "input": '<input autofocus onfocus="{H}">',
    "textarea": '<textarea autofocus onfocus="{H}"></textarea>',
    "select": '<select autofocus onfocus="{H}"><option>x</option></select>',
    "button": '<button autofocus onfocus="{H}">x</button>',
    "keygen": '<keygen autofocus onfocus="{H}">',
}
# autofocus 는 전역 속성이라 tabindex 로 포커스 가능해진 임의 요소에서도 로드 직후 발화한다.
FOCUS_TAGS = (
    "a", "div", "span", "section", "article", "p", "label", "strong", "em", "b",
    "i", "u", "mark", "small", "h1", "h2", "h3", "h4", "h5", "h6", "li", "td", "th",
    "blockquote", "pre", "code", "nav", "main", "aside", "header", "footer",
    "figure", "cite", "time", "data",
)
# ③ CSS 애니메이션은 요소가 그려지는 즉시 시작 → onanimationstart 가 조작 없이 실행된다.
CSS_TAGS = (
    "div", "span", "p", "a", "section", "article", "strong", "em", "b", "i", "u",
    "mark", "small", "h1", "h2", "h3", "h4", "h5", "h6", "li", "td", "th", "tr",
    "blockquote", "pre", "code", "nav", "main", "aside", "header", "footer",
    "figure", "figcaption", "caption", "ul", "ol", "dd", "dt",
)


def _build_vectors():
    out = list(AUTO_SPECIAL)
    for tag, template in FOCUS_CONTROL_TEMPLATES.items():
        out.append((tag, "onfocus", template))
    for tag in FOCUS_TAGS:
        out.append((tag, "onfocus", f'<{tag} tabindex="1" autofocus onfocus="{{H}}">x</{tag}>'))
    for tag in CSS_TAGS:
        out.append((tag, "onanimationstart",
                    _STYLE + f'<{tag} style="animation:{_KF} 1s" onanimationstart="{{H}}">x</{tag}>'))
    seen, uniq = set(), []
    for tag, event, template in out:
        if (tag, event) in seen:
            continue
        seen.add((tag, event))
        uniq.append((tag, event, template))
    if len(uniq) < 100:
        raise RuntimeError(f"자동 발화 조합이 100개 미만입니다: {len(uniq)}")
    return tuple(uniq[:100])


VECTORS = _build_vectors()

TEXT_OR_INERT = {
    "script", "style", "textarea", "title", "template", "noscript",
    "xmp", "iframe", "noembed", "noframes", "plaintext",
}


class HandlerCandidate(HTMLParser):
    """원문에서 태그와 이벤트 속성을 찾는 보수적인 검사입니다."""

    def __init__(self, tag, event, handler):
        super().__init__(convert_charrefs=True)
        self.expected_tag = tag
        self.event = event
        self.handler = handler
        self.inert = []
        self.match = None

    def handle_starttag(self, tag, attrs):
        if not self.inert and tag == self.expected_tag:
            value = next((value for name, value in attrs if name == self.event), None)
            if value == self.handler:
                self.match = self.getpos()
        if tag in TEXT_OR_INERT and (not self.inert or self.inert[-1] == "template"):
            self.inert.append(tag)

    def handle_endtag(self, tag):
        if self.inert and self.inert[-1] == tag and tag != "plaintext":
            self.inert.pop()


def response_evidence(response, tag, event, handler, marker):
    media_type = (response.header("Content-Type") or "").partition(";")[0].strip().lower()
    if marker not in response.body:
        return 0, media_type, ""
    if media_type == "text/html" and not 300 <= response.status < 400:
        parser = HandlerCandidate(tag, event, handler)
        parser.feed(response.body)
        parser.close()
        if parser.match is not None:
            line, column = parser.match
            return 2, media_type, f"HTML 이벤트 속성 후보. 응답 {line}행 {column + 1}열."
    return 1, media_type, "표식 반사. HTML 이벤트 속성 후보로 확인되지 않았습니다."


# ───────────────────────── DOM 기반 (정적 소스→싱크) ─────────────────────────
#
# 브라우저 없이 확인할 수 있는 것은 '공격자가 다루는 입력(소스)' 이 '값을 HTML/코드로
# 해석하는 지점(싱크)' 으로 흘러들 가능성이 있는지입니다. 둘이 같은 스크립트에 함께
# 있으면 DOM XSS '후보' 로 올립니다. 실제로 터지는지는 브라우저로 확인해야 합니다.

DOM_SOURCES = {
    "location.hash": r"location\s*\.\s*hash",
    "location.search": r"location\s*\.\s*search",
    "location.href": r"location\s*\.\s*href",
    "location(전체)": r"(?<![.\w])location(?!\s*\.\s*(assign|replace|reload))",
    "document.URL": r"document\s*\.\s*URL\b",
    "document.documentURI": r"document\s*\.\s*documentURI",
    "document.referrer": r"document\s*\.\s*referrer",
    "window.name": r"window\s*\.\s*name\b",
    "document.cookie": r"document\s*\.\s*cookie",
    "localStorage": r"\blocalStorage\b",
    "sessionStorage": r"\bsessionStorage\b",
    "postMessage(event.data)": r"\.\s*data\b.*?addEventListener\(\s*['\"]message|addEventListener\(\s*['\"]message",
    "URLSearchParams": r"\bURLSearchParams\b",
}

DOM_SINKS = {
    "innerHTML": r"\.\s*innerHTML\s*(?:[+]?=)",
    "outerHTML": r"\.\s*outerHTML\s*(?:[+]?=)",
    "insertAdjacentHTML": r"\.\s*insertAdjacentHTML\s*\(",
    "document.write": r"document\s*\.\s*write(?:ln)?\s*\(",
    "eval": r"(?<![.\w])eval\s*\(",
    "Function(생성)": r"(?<![.\w])Function\s*\(",
    "setTimeout(문자열)": r"setTimeout\s*\(\s*['\"]",
    "setInterval(문자열)": r"setInterval\s*\(\s*['\"]",
    "jQuery.html()": r"\.\s*html\s*\(",
    "jQuery.append/before/after": r"\.\s*(append|prepend|before|after|replaceWith)\s*\(",
    "jQuery $()(선택자+HTML)": r"\$\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"][^'\"]*<)",
    "setAttribute(위험)": r"\.\s*setAttribute\s*\(\s*['\"](?:href|src|on\w+)['\"]",
    "location 대입": r"(?:location(?:\s*\.\s*(href|assign|replace))?)\s*=\s*",
}

SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)""", re.I)
INLINE_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", re.I | re.S)
SOURCE_RES = {k: re.compile(v, re.I) for k, v in DOM_SOURCES.items()}
SINK_RES = {k: re.compile(v, re.I) for k, v in DOM_SINKS.items()}


def _same_origin(a, b):
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _scan_js(label, js):
    """스크립트 한 덩이에서 소스·싱크 위치를 모은다 → (소스목록, 싱크목록)."""
    found_sources, found_sinks = [], []
    for name, rx in SOURCE_RES.items():
        m = rx.search(js)
        if m:
            found_sources.append((name, label, _line_of(js, m.start())))
    for name, rx in SINK_RES.items():
        m = rx.search(js)
        if m:
            found_sinks.append((name, label, _line_of(js, m.start())))
    return found_sources, found_sinks


def dom_check(target, points, params):
    try:
        depth = int(params.get("dom_depth") or 20)
    except (TypeError, ValueError):
        depth = 20
    depth = max(0, min(depth, 40))

    pages = []
    seen = set()
    for point in points:
        if point.url not in seen:
            seen.add(point.url)
            pages.append(point)
    if not pages:
        raise ValueError("DOM 점검은 페이지가 있는 지점을 하나 이상 선택하세요.")

    results = []
    for point in pages:
        lines = [f"대상 페이지: {point.url}"]
        try:
            page = core.fetch(point.url)
        except (OSError, core.BudgetExceeded) as error:
            results.append(Check(point=point, verdict="potential",
                                 evidence=f"{point.url} 조회 실패: {error}"))
            continue

        media = (page.header("Content-Type") or "").partition(";")[0].strip().lower()
        if media and media != "text/html":
            results.append(Check(point=point, verdict="safe",
                                 evidence=f"{point.url} 은 HTML 이 아닙니다({media}). 건너뜁니다."))
            continue

        chunks = [("inline", m.group(1)) for m in INLINE_RE.finditer(page.body)]
        fetched = 0
        for raw in SRC_RE.findall(page.body):
            if fetched >= depth:
                break
            src = urljoin(point.url, raw)
            if not _same_origin(src, point.url):
                continue  # 외부 출처 스크립트는 읽지 않습니다
            fetched += 1
            try:
                js = core.fetch(src)
            except (OSError, core.BudgetExceeded):
                continue
            chunks.append((raw, js.body))

        all_sources, all_sinks = [], []
        for label, js in chunks:
            s, k = _scan_js(label, js)
            all_sources += s
            all_sinks += k

        lines.append(f"스크립트 {len(chunks)}덩이 분석(인라인 + 같은 출처 외부 {fetched}개).")
        if all_sources and all_sinks:
            src_txt = ", ".join(f"{n}({lbl}:{ln})" for n, lbl, ln in all_sources[:6])
            sink_txt = ", ".join(f"{n}({lbl}:{ln})" for n, lbl, ln in all_sinks[:6])
            lines.append(f"소스: {src_txt}")
            lines.append(f"싱크: {sink_txt}")
            lines.append("소스와 싱크가 같은 페이지 스크립트에 함께 있습니다 — DOM XSS 후보.")
            lines.append("두 지점이 실제로 이어지는지(데이터 흐름)와 실행 여부는 브라우저로 검증하세요.")
            verdict = "potential"
        elif all_sinks:
            sink_txt = ", ".join(f"{n}({lbl}:{ln})" for n, lbl, ln in all_sinks[:6])
            lines.append(f"위험 싱크만 발견: {sink_txt}. 공격자 입력 소스는 찾지 못했습니다.")
            verdict = "safe"
        else:
            lines.append("위험 싱크를 찾지 못했습니다(정적 기준).")
            verdict = "safe"
        results.append(Check(point=point, verdict=verdict, evidence="\n".join(lines), response=page))
    return results


# ───────────────────────── 저장형 ─────────────────────────
def _resolve_read_location(point, written, read_path, origin):
    """저장값을 읽을 위치를 정한다.

    우선순위: ① 사용자가 조회 경로를 적었으면 그 경로.
             ② 비었으면 저장(POST) 응답의 Location(새 글 주소)에서 자동으로 찾는다.
    둘 다 같은 출처(scheme+host)만 허용한다. → (조회 URL, 어떻게 정했는지) 또는 (None, "").
    """
    if read_path:
        read = urlsplit(read_path)
        if (not read_path.startswith("/") or read_path.startswith("//") or read.scheme
                or read.netloc or "#" in read_path or "\\" in read_path
                or any(ord(c) < 32 for c in read_path)):
            raise ValueError("조회 경로는 같은 대상의 /경로 형식으로 입력하세요.")
        url = urlunsplit((origin.scheme, origin.netloc, read.path, read.query, ""))
        return url, f"사용자 지정 경로 {read_path}"

    location = written.header("Location")
    if location:
        parts = urlsplit(urljoin(point.url, location))
        if (parts.scheme, parts.netloc) != (origin.scheme, origin.netloc):
            raise ValueError(f"저장 응답의 Location 이 다른 출처입니다: {location}")
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        return url, f"저장 응답 Location → {url} (새 글 자동 추출)"
    return None, ""


def stored_check(target, points, params):
    if params.get("write_ack", "").strip() != "WRITE":
        raise ValueError("저장형은 저장 허용 확인 칸에 WRITE를 입력해야 합니다.")
    if len(points) != 1 or (points[0].method, points[0].place) != ("POST", "form"):
        raise ValueError("저장형은 POST 폼 파라미터를 정확히 하나 선택하세요.")
    point = points[0]
    origin = urlsplit(target.url)
    write_url = urlsplit(point.url)
    if (write_url.scheme, write_url.netloc) != (origin.scheme, origin.netloc):
        raise ValueError("저장 폼은 선택한 대상과 같은 출처여야 합니다.")

    index = int(params.get("stored_vector") or 1)
    if not 1 <= index <= len(VECTORS):
        raise ValueError("저장할 테스트 값 번호는 1~100이어야 합니다.")
    tag, event, template = VECTORS[index - 1]
    marker = probe.marker()
    handler = HANDLER.replace("{T}", marker)
    sent = template.replace("{H}", handler)
    read_path = (params.get("read_path") or "").strip()
    read_headers = {"Cache-Control": "no-cache"}

    # 표식(marker)은 요청마다 새로 만드는 고유값이라, 조회 응답에 보이면 '이번에 저장된 것' 입니다.
    # (CSRF 토큰은 없다고 가정하고 보냅니다. 함께 보낼 다른 필드는 point.fields 에서 채워집니다.)
    lines = [
        f"저장형 조합 {index}: {tag} / {event}",
        f"표식: {marker}",
        f"저장 폼: POST {point.url}  [주입 필드: {point.param}]"
        + (f" · 함께 보낸 필드 {len(point.fields)}개" if point.fields else " · 함께 보낸 필드 없음"),
        "테스트 데이터는 사용자가 정리해야 합니다.",
    ]
    try:
        written = probe.send(point, sent)
    except OSError as error:
        lines.append(f"POST 응답을 받지 못했습니다: {error}. 재실행 전에 저장 여부를 확인하세요.")
        return Check(point=point, verdict="potential", evidence="\n".join(lines))
    lines.append(f"POST {point.url} → HTTP {written.status}")
    if not 200 <= written.status < 400:
        lines.append("저장 응답이 실패 상태입니다. 필수 필드가 비었거나 거부됐을 수 있습니다.")
        return Check(point=point, verdict="potential", response=written, evidence="\n".join(lines))

    read_url, how = _resolve_read_location(point, written, read_path, origin)
    if not read_url:
        lines.append("저장 응답에 새 글 주소(Location)가 없고 조회 경로도 비었습니다. "
                     "조회 경로를 직접 입력하거나 저장 위치를 확인하세요.")
        return Check(point=point, verdict="potential", response=written, evidence="\n".join(lines))
    lines.append(f"조회 위치: {how}")

    try:
        observed = core.fetch(read_url, headers=read_headers)
    except (OSError, core.BudgetExceeded) as error:
        lines.append(f"저장 후 조회에 실패했습니다: {error}")
        return Check(point=point, verdict="potential", response=written, evidence="\n".join(lines))

    lines.append(f"GET {read_url} → HTTP {observed.status}")
    if not 200 <= observed.status < 300:
        lines.append("조회 응답이 실패 상태여서 저장형 여부를 판단할 수 없습니다.")
        return Check(point=point, verdict="potential", response=observed, evidence="\n".join(lines))

    rank, media_type, detail = response_evidence(observed, tag, event, handler, marker)
    if rank:
        lines.append(f"저장된 표식을 조회 응답에서 확인했습니다. {media_type or 'Content-Type 없음'}.")
        lines.append(detail.replace("표식 반사.", "저장된 표식 확인."))
    else:
        lines.append("조회 응답에서 표식을 찾지 못했습니다(저장되지 않았거나 다른 위치일 수 있습니다).")
    lines.append("HTTP 응답 기준입니다. 브라우저 실행 여부는 별도 검증이 필요합니다.")
    return Check(point=point, verdict="potential" if rank else "safe",
                 response=observed, evidence="\n".join(lines))


# ───────────────────────── 진입점 ─────────────────────────
def run(target, points, params):
    mode = params.get("mode")
    if mode == "stored":
        return [stored_check(target, points, params)]
    if mode == "dom":
        return dom_check(target, points, params)

    limit = int(params.get("limit") or len(VECTORS))
    if not 1 <= limit <= len(VECTORS):
        raise ValueError("지점당 테스트 값 수는 1~100으로 입력하세요.")

    eligible = [
        point for point in points
        if point.method == "GET" and point.place == "query" and point.param
    ]
    if not eligible:
        raise ValueError("GET 쿼리 파라미터를 하나 이상 선택하세요.")

    results = []
    for point in eligible:
        best_rank, best_response = 0, None
        best_lines = []
        completed = 0
        for tag, event, template in VECTORS[:limit]:
            marker = probe.marker()
            handler = HANDLER.replace("{T}", marker)
            sent = template.replace("{H}", handler)
            response = probe.send(point, sent)
            completed += 1
            if response.status == 429:
                results.append(Check(
                    point=point, verdict="potential", response=best_response or response,
                    evidence="\n".join([*best_lines, "HTTP 429로 이후 요청을 중단했습니다."]),
                ))
                return results
            rank, media_type, detail = response_evidence(response, tag, event, handler, marker)
            if rank > best_rank:
                best_rank, best_response = rank, response
                best_lines = [
                    f"테스트 조합: {tag} / {event}",
                    f"입력값: {sent}",
                    f"HTTP {response.status} · {media_type or 'Content-Type 없음'}",
                    detail,
                ]

        evidence = [
            f"테스트 값 {completed}개 전송.",
            *(best_lines or ["수신한 응답 본문에서 표식이 확인되지 않았습니다."]),
            "HTTP 응답 기준입니다. 브라우저 실행 여부는 별도 검증이 필요합니다.",
        ]
        results.append(Check(
            point=point, verdict="potential" if best_rank else "safe",
            evidence="\n".join(evidence), response=best_response,
        ))
    return results
