"""새싹에듀용 반사형·저장형 XSS 후보 탐색 모듈.

PortSwigger Web Security Academy의 Event handlers를 참고해 작성한 테스트 값입니다.
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#event-handlers
브라우저에서 실행되면 고유 표식을 콘솔에 기록합니다. 브라우저는 이 모듈에서 실행하지 않습니다.
"""

from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from dashboard import core, probe
from dashboard.core import Check


META = {
    "id": "sesacedu_xss_probe",
    "name": "새싹에듀 반사형·저장형 XSS 후보 탐색",
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
        "반사형은 GET 쿼리를 점검합니다. 저장형은 테스트 폼을 한 번 제출하고 "
        "별도 GET으로 읽습니다. 브라우저 실행 여부는 별도 검증이 필요합니다."
    ),
    "params": [
        {"name": "mode", "need": "required", "type": "select", "default": "reflected",
         "label": "점검 모드", "options": [
             {"value": "reflected", "label": "반사형 (GET)"},
             {"value": "stored", "label": "저장형 (POST 폼 1회 + GET 조회)"},
         ]},
        {"name": "limit", "need": "optional", "type": "int", "default": "100",
         "label": "지점당 테스트 값 수 (1~100)",
         "help": "반사형 전용. 100개를 선택하면 지점 1개당 최대 100회 요청합니다."},
        {"name": "read_path", "need": "conditional", "when": "저장형 모드",
         "label": "저장값을 조회할 경로", "default": "",
         "help": "같은 대상에서 저장 후 해당 값이 보이는 GET 경로. 예: /test/posts"},
        {"name": "stored_vector", "need": "conditional", "when": "저장형 모드",
         "type": "int", "default": "1", "label": "저장할 테스트 값 번호 (1~100)",
         "help": "선택한 조합 하나만 저장합니다. 1번은 img/onerror입니다."},
        {"name": "write_ack", "need": "conditional", "when": "저장형 모드",
         "label": "저장 허용 확인", "default": "",
         "help": "삭제 가능한 테스트 데이터에서만 실행하고, 확인 칸에 WRITE를 입력하세요."},
    ],
}

HANDLER = "console.log('{T}')"

# 처음 10개는 자동 이벤트, 포커스 및 입력 요소 위주로 배치합니다.
SPECIAL_VECTORS = (
    ("img", "onerror", '<img src="data:," onerror="{H}">'),
    ("svg", "onload", '<svg onload="{H}"></svg>'),
    ("details", "ontoggle", '<details open ontoggle="{H}"><summary>Test</summary></details>'),
    ("input", "onfocus", '<input autofocus onfocus="{H}">'),
    ("textarea", "onfocus", '<textarea autofocus onfocus="{H}"></textarea>'),
    ("animate", "onbegin", '<svg><rect width="5" height="5"><animate attributeName="x" from="0" to="1" dur="1s" onbegin="{H}"/></rect></svg>'),
    ("iframe", "onload", '<iframe src="about:blank" onload="{H}"></iframe>'),
    ("select", "onchange", '<select onchange="{H}"><option>A</option><option>B</option></select>'),
    ("input", "oninput", '<input oninput="{H}">'),
    ("textarea", "onpaste", '<textarea onpaste="{H}"></textarea>'),
)

# 9개 이벤트를 10개 태그에 적용합니다. 대부분 포커스, 키보드 또는 포인터 조작이 필요합니다.
INTERACTION_EVENTS = (
    "onmouseover", "onfocus", "onpointerover", "onmouseenter", "oncontextmenu",
    "ondblclick", "onmousedown", "onmousemove", "onkeydown",
)
INTERACTION_TAGS = (
    ("div", ""), ("span", ""), ("section", ""), ("article", ""), ("p", ""),
    ("strong", ""), ("label", ""), ("a", ""), ("button", ' type="button"'),
    ("summary", ""),
)


def interaction_vector(tag, attrs, event):
    element = f'<{tag}{attrs} tabindex="0" {event}="{{H}}">XSS test</{tag}>'
    if tag == "summary":
        return f"<details>{element}</details>"
    return element


VECTORS = SPECIAL_VECTORS + tuple(
    (tag, event, interaction_vector(tag, attrs, event))
    for event in INTERACTION_EVENTS
    for tag, attrs in INTERACTION_TAGS
)

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

    path = params.get("read_path", "").strip()
    read = urlsplit(path)
    if (not path.startswith("/") or path.startswith("//") or read.scheme
            or read.netloc or "#" in path or "\\" in path or any(ord(c) < 32 for c in path)):
        raise ValueError("조회 경로는 같은 대상의 /경로 형식으로 입력하세요.")
    read_url = urlunsplit((origin.scheme, origin.netloc, read.path, read.query, ""))

    index = int(params.get("stored_vector") or 1)
    if not 1 <= index <= len(VECTORS):
        raise ValueError("저장할 테스트 값 번호는 1~100이어야 합니다.")
    tag, event, template = VECTORS[index - 1]
    marker = probe.marker()
    handler = HANDLER.replace("{T}", marker)
    sent = template.replace("{H}", handler)
    read_headers = {"Cache-Control": "no-cache"}

    baseline = core.fetch(read_url, headers=read_headers)
    if not 200 <= baseline.status < 300 or marker in baseline.body:
        raise ValueError(f"저장 전 조회를 확인할 수 없습니다(HTTP {baseline.status}). POST를 보내지 않았습니다.")

    lines = [
        f"저장형 조합 {index}: {tag} / {event}",
        f"표식: {marker}",
        "테스트 데이터는 사용자가 정리해야 합니다.",
    ]
    try:
        written = probe.send(point, sent)
    except OSError as error:
        lines.append(f"POST 응답을 받지 못했습니다: {error}. 재실행 전에 저장 여부를 확인하세요.")
        return Check(point=point, verdict="potential", evidence="\n".join(lines))
    lines.append(f"POST {point.url} → HTTP {written.status}")
    if not 200 <= written.status < 400:
        lines.append("저장 응답이 실패 상태입니다. 저장 여부를 확인하세요.")
        return Check(point=point, verdict="potential", response=written, evidence="\n".join(lines))

    try:
        observed = core.fetch(read_url, headers=read_headers)
    except (OSError, core.BudgetExceeded) as error:
        lines.append(f"저장 후 조회에 실패했습니다: {error}")
        return Check(point=point, verdict="potential", response=written, evidence="\n".join(lines))

    lines.append(f"별도 GET {read_url} → HTTP {observed.status}")
    if not 200 <= observed.status < 300:
        lines.append("조회 응답이 실패 상태여서 저장형 여부를 판단할 수 없습니다.")
        return Check(point=point, verdict="potential", response=observed, evidence="\n".join(lines))

    rank, media_type, detail = response_evidence(observed, tag, event, handler, marker)
    if rank:
        lines.append(f"저장 전에는 없던 표식을 별도 GET에서 확인했습니다. {media_type or 'Content-Type 없음'}.")
        lines.append(detail.replace("표식 반사.", "저장된 표식 확인."))
    else:
        lines.append("지정한 조회 응답에서 표식을 찾지 못했습니다.")
    lines.append("HTTP 응답 기준입니다. 브라우저 실행 여부는 별도 검증이 필요합니다.")
    return Check(point=point, verdict="potential" if rank else "safe",
                 response=observed, evidence="\n".join(lines))


def run(target, points, params):
    if params.get("mode") == "stored":
        return [stored_check(target, points, params)]

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
