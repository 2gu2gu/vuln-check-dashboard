"""같은 사이트 안의 링크·폼·스크립트를 따라가며 엔드포인트와 파라미터를 모은다(GET 만 보냄)."""
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from dashboard.core import Point, fetch

META = {
    "id": "surface_crawl",
    "name": "페이지 따라가며 수집",
    "category": "표면 수집",
    "kind": "passive",
    "stage": "collect",
    "attack": [{"tactic": "TA0043", "technique": "T1594", "name": "Search Victim-Owned Websites"}],
    "description": "링크(쿼리 파라미터), 폼(입력칸 이름·메서드), 스크립트 안의 /api 경로를 모읍니다. 폼은 제출하지 않습니다.",
    "params": [
        {"name": "start", "label": "시작 경로", "default": "/"},
        {"name": "max_pages", "label": "최대 페이지", "default": "30", "type": "int"},
        {"name": "skip", "label": "제외할 말(쉼표)", "default": "logout,signout,delete,remove"},
    ],
}

SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|pdf|zip|mp4|mp3|avi|mov)$", re.I)
JS_PATH = re.compile(r"""["'`]((?:https?://[^"'`\s]+)?/(?:api|v\d+)/[^"'`\s<>]*)["'`]""")
MAX_SCRIPTS = 15


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts, self.forms, self.inline_js = [], [], [], []
        self._form = None
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "area") and a.get("href"):
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


def _split(url):
    """(쿼리 뺀 주소, [(이름, 값)])"""
    s = urlsplit(url)
    return urlunsplit((s.scheme, s.netloc, s.path or "/", "", "")), parse_qsl(s.query, keep_blank_values=True)


def _query_points(url, source, method="GET"):
    base, pairs = _split(url)
    out = [Point(method, base, place="path", source=source)]
    out += [Point(method, base, param=k, place="query", sample=v, source=source) for k, v in pairs]
    return out


def _js_points(text, page_url, host):
    out = []
    for m in JS_PATH.finditer(text):
        url = urljoin(page_url, m.group(1))
        if urlsplit(url).hostname == host:
            out += _query_points(url, "js")
    return out


def run(target, params):
    host = urlsplit(target.url).hostname
    skip = [w.strip().lower() for w in params.get("skip", "").split(",") if w.strip()]
    limit = max(1, int(params.get("max_pages") or 30))
    queue, seen, scripts_seen, points = [urljoin(target.url + "/", params.get("start") or "/")], set(), set(), []

    def ok(url):
        s = urlsplit(url)
        return (s.scheme in ("http", "https") and s.hostname == host and not SKIP_EXT.search(s.path)
                and not any(w in url.lower() for w in skip))

    while queue and len(seen) < limit:
        url = queue.pop(0).split("#")[0]
        if url in seen or not ok(url):
            continue
        seen.add(url)
        try:
            r = fetch(url)
        except OSError:  # 한 페이지가 끊겨도 나머지는 계속
            continue
        points += _query_points(url, "link")
        if "html" not in r.header("Content-Type").lower():
            continue
        page = _Page()
        page.feed(r.body)
        for href in page.links:
            nxt = urljoin(url, href).split("#")[0]
            if ok(nxt) and nxt not in seen:
                queue.append(nxt)
        for f in page.forms:
            # action 의 쿼리는 버린다: GET 폼은 브라우저가 입력칸으로 갈아 끼우고, POST 폼이면 본문이 아니다
            action, _ = _split(urljoin(url, f["action"] or url))
            if urlsplit(action).hostname != host:
                continue
            place = "form" if f["method"] == "POST" else "query"
            points.append(Point(f["method"], action, place="path", source="form"))
            points += [Point(f["method"], action, param=n, place=place, sample=v, source="form")
                       for n, v in f["fields"]]
        for js in page.inline_js:
            points += _js_points(js, url, host)
        for src in page.scripts:
            js_url = urljoin(url, src)
            if urlsplit(js_url).hostname == host and js_url not in scripts_seen and len(scripts_seen) < MAX_SCRIPTS:
                scripts_seen.add(js_url)
                try:
                    points += _js_points(fetch(js_url).body, url, host)
                except OSError:
                    pass

    # 같은 지점은 하나로
    unique = {}
    for p in points:
        unique.setdefault((p.method, p.url, p.param, p.place), p)
    return list(unique.values())
