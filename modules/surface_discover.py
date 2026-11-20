"""표면 자동 수집: 페이지·robots·API 명세·JS 를 읽어 엔드포인트와 파라미터를 모으고,
있는지 확인한 뒤 위험 점수를 붙인다. 보내는 요청은 GET 과 OPTIONS 뿐이다.

흐름은 팀원이 넘겨 준 endpoint_discovery.py(11-20)의 단계를 따랐고, 요청은 모두
core.fetch 로 보낸다 — 범위 검사·요청 간격·요청 기록이 그대로 걸린다.
부품은 dashboard/discovery.py.
"""
import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from dashboard import discovery as dv
from dashboard.core import Point, fetch

META = {
    "id": "surface_discover",
    "hidden": True,  # 표면 수집(surface_collect)이 부품으로 쓴다 — 목록에 따로 안 띄운다(11-20)
    "name": "표면 자동 수집",
    "category": "표면 수집",
    "kind": "active",
    "stage": "collect",
    "attack": [
        {"tactic": "TA0043", "technique": "T1594", "name": "Search Victim-Owned Websites"},
        {"tactic": "TA0043", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning"},
    ],
    "description": "페이지·폼·robots·sitemap·**API 명세(OpenAPI·Spring Actuator)**·**JS 번들**(fetch·axios 호출, "
                   "`/backend/...` 경로, 본문 키)을 읽어 엔드포인트와 파라미터를 모읍니다. 모은 경로가 정말 있는지 "
                   "없는 주소의 응답과 비교해 확인하고(가짜 200 걸러냄) 위험 점수를 붙입니다. GET·OPTIONS 만 보냅니다. "
                   "단계에 `guess`(있을 법한 경로 예측)·`params`(숨은 파라미터 찾기)를 더하면 요청이 늘어납니다.",
    "params": [
        {"name": "steps", "need": "optional", "label": "단계(쉼표)", "default": "page,meta,spec,js,verify",
         "placeholder": "page,meta,spec,js,verify,guess,params"},
        {"name": "start", "need": "optional", "label": "시작 경로", "default": "/"},
        {"name": "max_pages", "need": "optional", "label": "최대 페이지", "default": "30", "type": "int"},
        {"name": "max_scripts", "need": "optional", "label": "최대 JS 파일", "default": "40", "type": "int"},
        {"name": "max_verify", "need": "optional", "label": "확인할 후보 수", "default": "150", "type": "int"},
        {"name": "skip", "need": "optional", "label": "제외할 단어(쉼표)", "default": "logout,signout,delete,remove"},
        {"name": "max_guesses", "need": "conditional", "when": "단계에 guess 를 넣을 때만", "label": "예측 후보 수",
         "default": "100", "type": "int"},
        {"name": "mine_max", "need": "conditional", "when": "단계에 params 를 넣을 때만",
         "label": "숨은 파라미터 찾을 주소 수", "default": "5", "type": "int"},
    ],
}

SKIP_PAGE = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|pdf|zip|mp4|mp3|avi|mov|js|map)$", re.I)
STEP_LABEL = {"page": "페이지", "meta": "robots·sitemap", "spec": "API 명세", "js": "JS", "verify": "확인",
              "guess": "예측", "params": "숨은 파라미터"}


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts, self.forms, self.inline_js = [], [], [], []
        self._form, self._in_script = None, False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "area", "link") and a.get("href") and tag != "link":
            self.links.append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "GET").upper(), "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None and a.get("name"):
            if (a.get("type") or "").lower() not in ("submit", "button", "image", "reset"):
                self._form["fields"].append((a["name"], a.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.inline_js.append(data)


def run(target, params):
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(target.url))
    host = urlsplit(target.url).netloc
    steps = {s.strip() for s in (params.get("steps") or "").split(",") if s.strip()} or set(STEP_LABEL)
    skip = [w.strip().lower() for w in (params.get("skip") or "").split(",") if w.strip()]
    reg = dv.Registry()
    scripts = []                         # 읽을 JS 주소(순서 유지)

    def allowed(url):
        s = urlsplit(url)
        return s.scheme in ("http", "https") and s.netloc == host and not any(w in url.lower() for w in skip)

    def get(url):
        return fetch(url)


    # ── 1 페이지: 링크·폼·스크립트 ──
    if "page" in steps:
        limit = max(1, int(params.get("max_pages") or 30))
        queue, seen = [urljoin(target.url + "/", params.get("start") or "/")], set()
        while queue and len(seen) < limit:
            url = queue.pop(0).split("#")[0]
            if url in seen or not allowed(url) or SKIP_PAGE.search(urlsplit(url).path):
                continue
            seen.add(url)
            try:
                r = get(url)
            except OSError:
                continue
            if r.status >= 400:
                continue
            q = urlsplit(url).query
            reg.add("GET", url, "link", evidence="페이지 링크", kind="api" if q else "page")
            if "html" not in r.header("Content-Type").lower():
                continue
            page = _Page()
            page.feed(r.body)
            for href in page.links:
                nxt = urljoin(url, href).split("#")[0]
                if allowed(nxt) and nxt not in seen:
                    queue.append(nxt)
            for f in page.forms:
                action = urljoin(url, f["action"] or url)
                if not allowed(action):
                    continue
                place = "form" if f["method"] == "POST" else "query"
                reg.add(f["method"], action.split("?")[0], "form",
                        params={n: (place, v) for n, v in f["fields"]},
                        evidence=f"HTML 폼 — method={f['method']} 선언(제출하지 않음)")
            for js in page.inline_js:
                dv.extract_js(js, url, reg, where="인라인 스크립트")
            for src in page.scripts:
                js_url = urljoin(url, src)
                if urlsplit(js_url).netloc == host and js_url not in scripts:
                    scripts.append(js_url)

    # ── 2 robots · sitemap ──
    if "meta" in steps:
        sitemaps = [origin + "/sitemap.xml"]
        try:
            r = get(origin + "/robots.txt")
            if r.status == 200 and "html" not in r.header("Content-Type").lower():
                sitemaps += dv.parse_robots(r.body, origin, reg)
        except OSError:
            pass
        done = set()
        while sitemaps and len(done) < 5:
            sm = sitemaps.pop(0)
            if sm in done or not allowed(sm):
                continue
            done.add(sm)
            try:
                r = get(sm)
            except OSError:
                continue
            if r.status == 200:
                sitemaps += dv.parse_sitemap(r.body, origin, reg)

    # ── 3 API 명세 ──
    if "spec" in steps:
        for path in dv.SPEC_PATHS:
            try:
                r = get(origin + path)
            except OSError:
                continue
            doc = dv.load_json(r.body) if r.status == 200 else None
            if doc and dv.parse_openapi(doc, origin + path, origin, reg, get=get):
                reg.add("GET", origin + path, "spec", evidence="API 명세 문서가 인증 없이 열림")
                break
        for path in dv.ACTUATOR_PATHS:
            try:
                r = get(origin + path)
            except OSError:
                continue
            doc = dv.load_json(r.body) if r.status == 200 else None
            if doc and dv.parse_actuator_mappings(doc, origin, reg):
                reg.add("GET", origin + path, "spec", evidence="Spring Actuator 매핑 목록이 인증 없이 열림")
                break

    # ── 4 JS 번들 ──
    if "js" in steps:
        limit = max(0, int(params.get("max_scripts") or 40))
        maps = 0
        for js_url in scripts[:limit]:
            try:
                r = get(js_url)
            except OSError:
                continue
            if r.status != 200:
                continue
            name = urlsplit(js_url).path.rsplit("/", 1)[-1]
            if "_buildManifest" in name:
                dv.extract_build_manifest(r.body, origin + "/", reg)
            dv.extract_js(r.body, origin + "/", reg, where=f"JS {name}")
            sm = dv.sourcemap_url(r.body, js_url)
            if sm and maps < 5 and allowed(sm):
                maps += 1
                try:
                    m = get(sm)
                    if m.status == 200:
                        for src in dv.sourcemap_sources(m.body):
                            dv.extract_js(src, origin + "/", reg, where=f"소스맵 {name}.map")
                except OSError:
                    pass

    # ── 5 있는지 확인 ──
    # ── 6 예측(선택): 아는 경로에서 있을 법한 경로를 만든다. 확인에서 걸러진다 ──
    if "guess" in steps:
        dv.guess(reg, origin + "/", limit=max(0, int(params.get("max_guesses") or 100)))

    if "verify" in steps or "guess" in steps:
        v = dv.Verifier(get, options=lambda u: fetch(u, method="OPTIONS"))
        found = sorted((c for c in reg if c.sources != ["guess"]), key=lambda c: (-c.confidence(), c.path))
        guessed = [c for c in reg if c.sources == ["guess"]]     # 예측은 따로 센다 — 상한에 밀려 안 보이지 않게
        todo = (found[: max(0, int(params.get("max_verify") or 150))] if "verify" in steps else []) + guessed
        for c in todo:
            if allowed(c.url):
                v.check(c)
        dv.drop_unconfirmed_guesses(reg)

    # ── 7 숨은 파라미터(선택): 있다고 확인된 GET 몇 개에 이름 후보를 붙여 본다 ──
    if "params" in steps:
        picks = [c for c in reg if c.method == "GET" and c.kind == "api" and c.state == "exists"
                 and allowed(c.url) and "{" not in c.path]
        picks.sort(key=lambda c: (-len(c.params), c.path))
        for c in picks[: max(0, int(params.get("mine_max") or 5))]:
            dv.mine_params(c, get)

    return _to_points(reg)


def _to_points(reg):
    points = []
    for c in reg:
        dv.score(c)
        ev = json.dumps({
            "sources": c.sources, "basis": c.basis(), "evidence": c.evidence, "reasons": c.reasons,
            "confidence": c.confidence(), "kind": c.kind,
        }, ensure_ascii=False)
        common = dict(source=",".join(c.sources), state=c.state, status=c.status, evidence=ev, risk=c.risk)
        points.append(Point(c.method, c.url, place="path", **common))
        for name, (place, sample) in c.params.items():
            points.append(Point(c.method, c.url, param=name, place=place, sample=sample, **common))
    return points
