"""표면 자동 수집이 쓰는 부품: 후보 모으기 → 있는지 확인 → 위험 점수.

요청은 보내지 않는다. 받은 본문을 읽어 후보(Candidate)를 만들고, 확인은 호출하는 쪽이
넘겨 준 get(url) 로 한다. 그래서 모든 요청이 core.fetch 의 범위 검사·간격·기록을 거친다.

뼈대는 팀원이 넘겨 준 endpoint_discovery.py(11-20, 단계 P1~P8)의 흐름을 따랐다.
- 후보마다 **어디서 알았는지(sources)와 근거(evidence)** 를 남긴다. 메서드도 근거가 다르다:
  HTML 폼·API 명세는 '선언', JS 문자열은 '추정'.
- 있는지는 **없는 주소에 대한 응답(기준)과 비교**해 판단한다. 아무 주소에나 200 과
  같은 화면을 주는 서버(soft-404)가 흔해서 상태 코드만 보면 틀린다.
- 확인에는 GET·OPTIONS 만 쓴다. 상태를 바꾸는 메서드는 보내지 않는다.
"""
import hashlib
import json
import random
import re
import string
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

# 근거별 신뢰도 — 같은 후보가 여러 곳에서 나오면 합쳐서 올라간다
SOURCE_CONFIDENCE = {"har": 0.99, "spec": 0.95, "form": 0.9, "link": 0.9, "meta": 0.6, "js": 0.5,
                     "manifest": 0.6, "guess": 0.15}
SOURCE_LABEL = {"link": "링크", "form": "폼", "js": "JS", "spec": "API 명세", "meta": "robots·sitemap",
                "manifest": "화면 경로표", "har": "HAR(관찰)", "guess": "예측", "mine": "숨은 파라미터"}
# 메서드를 무엇으로 알았나 — HAR 는 브라우저가 실제로 보낸 것이라 '관찰'
METHOD_BASIS = {"link": "선언", "form": "선언", "spec": "선언", "meta": "선언", "manifest": "선언", "js": "추정",
                "har": "관찰", "guess": "추정"}

STATES = {
    "exists": "있음", "auth_required": "인증 필요", "method_mismatch": "메서드 안 맞음",
    "server_error": "서버 오류", "redirect": "리다이렉트", "not_found": "없음",
    "soft_404": "없음(가짜 200)", "unverified": "미확인",
}

STATIC_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|avif|css|woff2?|ttf|eot|otf|map|mp4|mp3|webm|pdf|zip|"
                        r"txt|md|ts|tsx|jsx|scss|less)$", re.I)
SCRIPT_EXT = re.compile(r"\.m?js$", re.I)
# 숫자·UUID·긴 16진수 칸은 같은 엔드포인트의 다른 값이다
ID_SEG = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,})$", re.I)
SPEC_PATHS = ["/v3/api-docs", "/v2/api-docs", "/swagger.json", "/openapi.json", "/api-docs",
              "/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json",
              "/backend/v3/api-docs", "/backend/v2/api-docs"]
# Spring Boot 는 이 하나에 매핑된 경로가 전부 나온다
ACTUATOR_PATHS = ["/actuator/mappings", "/backend/actuator/mappings"]
# 명세 문서 이름만 떼어 낸 것 — 명세를 찾은 자리에서 접두사를 되찾는 데 쓴다(긴 것부터 맞춘다)
SPEC_TAILS = sorted(["/v3/api-docs", "/v2/api-docs", "/swagger.json", "/openapi.json", "/api-docs",
                     "/swagger/v1/swagger.json"], key=len, reverse=True)


@dataclass
class Candidate:
    method: str
    url: str                                   # 쿼리 뺀 절대 주소. 경로 변수는 {이름}
    params: dict = field(default_factory=dict)  # 이름 → (위치, 예시 값)
    sources: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    state: str = "unverified"
    status: int = 0
    risk: int = 0
    reasons: list = field(default_factory=list)
    kind: str = "api"                          # api / page(화면 경로)

    @property
    def path(self):
        return urlsplit(self.url).path or "/"

    def basis(self):
        """메서드를 무엇으로 알았는지 — 관찰(HAR) > 선언(HTML·명세) > 추정(JS·예측)."""
        kinds = {METHOD_BASIS.get(s) for s in self.sources}
        return "관찰" if "관찰" in kinds else ("선언" if "선언" in kinds else "추정")

    def confidence(self):
        miss = 1.0
        for s in self.sources:
            miss *= 1 - SOURCE_CONFIDENCE.get(s, 0.3)
        c = 1 - miss
        if self.state in ("exists", "auth_required", "method_mismatch", "server_error", "redirect"):
            c = max(c, 0.9)
        elif self.state in ("not_found", "soft_404"):
            c *= 0.2
        return round(c, 2)


class Registry:
    """(메서드, 주소) 하나에 후보 하나. 다른 곳에서 또 나오면 근거·파라미터를 합친다."""

    def __init__(self):
        self.items = {}

    def add(self, method, url, source, *, params=None, evidence="", kind="api"):
        method = (method or "GET").upper()
        s = urlsplit(url)
        path = normalize_path(s.path or "/")
        base = urlunsplit((s.scheme, s.netloc, path, "", ""))
        c = self.items.get((method, base))
        if c is None:
            c = self.items[(method, base)] = Candidate(method, base, kind=kind)
        if kind == "api":
            c.kind = "api"
        if source not in c.sources:
            c.sources.append(source)
        if evidence and evidence not in c.evidence and len(c.evidence) < 8:
            c.evidence.append(evidence)
        for k, v in parse_qsl(s.query, keep_blank_values=True):
            c.params.setdefault(k, ("query", v))
        for seg in re.findall(r"\{([^}/]+)\}", path):
            c.params.setdefault(seg, ("path", ""))
        for k, (place, sample) in (params or {}).items():
            if k and len(k) <= 60:
                c.params.setdefault(k, (place, sample))
        return c

    def __iter__(self):
        return iter(self.items.values())

    def __len__(self):
        return len(self.items)


def normalize_path(path):
    """/lectures/123 → /lectures/{id}. 이미 {이름} 인 칸과 :id 같은 라우터 표기도 맞춘다."""
    segs = []
    for seg in path.split("/"):
        if ID_SEG.match(seg):
            seg = "{id}"
        elif re.fullmatch(r":([A-Za-z_]\w*)", seg):
            seg = "{" + seg[1:] + "}"
        elif re.fullmatch(r"\[\.{0,3}([A-Za-z_]\w*)\]", seg):    # Next.js [id], [...slug]
            seg = "{" + re.sub(r"[\[\]\.]", "", seg) + "}"
        segs.append(seg)
    out = "/".join(segs)
    return out if out.startswith("/") else "/" + out


# ── JS 읽기 ──────────────────────────────────────────────────

# 따옴표·백틱 안의 '/' 로 시작하는 경로. /api 로 시작하지 않아도 잡는다 — 새싹에듀는 /backend 다
_JS_STR = re.compile(r"""(["'`])((?:https?://[\w.:-]+)?/[\w\-./{}$:?=&%~+]*)\1""")
_TEMPLATE = re.compile(r"\$\{\s*([^}]*?)\s*\}")
# "/a/" + id + "/b" 처럼 이어 붙인 경로
_CONCAT = re.compile(r"""(["'])(/[\w\-./]*)\1\s*\+\s*([A-Za-z_$][\w.$]*)(?:\s*\+\s*(["'])([\w\-./?=&]*)\4)?""")
_CALL = re.compile(r"""\b(fetch|axios(?:\.(get|post|put|patch|delete|head))?|\$\.(ajax|get|post)|"""
                   r"""(?:http|api|client|instance|request)\.(get|post|put|patch|delete))\s*\(""", re.I)
_METHOD_OPT = re.compile(r"""\b(?:method|type)\s*:\s*["'](GET|POST|PUT|PATCH|DELETE)["']""", re.I)
_OBJ_KEYS = re.compile(r"""(?:^|[{,])\s*["']?([A-Za-z_$][\w$]*)["']?\s*(?=[:,}])""")
_BUILD_MANIFEST = re.compile(r"""["'](/[\w\-./\[\]]*)["']\s*:\s*\[""")
_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


def _clean_path(raw):
    """JS 문자열 하나를 경로로 다듬는다. 경로가 아니면 None."""
    raw = _TEMPLATE.sub(lambda m: "{" + (re.sub(r"\W", "", m.group(1).split(".")[-1]) or "v") + "}", raw)
    if "$" in raw or "//" in raw.split("://", 1)[-1]:
        return None
    path = urlsplit(raw).path
    if len(path) < 2 or len(path) > 200 or path.count("/") > 12:
        return None
    if STATIC_EXT.search(path) or SCRIPT_EXT.search(path):
        return None
    if not re.search(r"[A-Za-z]{2}", path):        # '/', '/1', '/-' 같은 조각
        return None
    if re.search(r"[A-Z]{2,}\b|\s", path) and not re.search(r"[a-z]", path):
        return None
    return raw


def _concat_raw(m):
    """_CONCAT 한 건 → "/a/{id}/b" """
    tail = "/" + m.group(5).lstrip("/") if m.group(5) else ""
    return m.group(2).rstrip("/") + "/{" + m.group(3).split(".")[-1] + "}" + tail


def _args_after(text, start, limit=500):
    """호출의 괄호 안 내용(대충). 짝 맞는 ')' 까지, 너무 길면 자른다."""
    depth, i = 1, start
    end = min(len(text), start + limit)
    while i < end and depth:
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        i += 1
    return text[start:i - 1] if depth == 0 else text[start:end]


def _object_keys(block, name):
    """`name: { a: 1, b }` 또는 JSON.stringify({ ... }) 안의 키."""
    m = re.search(name + r"""\s*:\s*(?:JSON\.stringify\()?\{([^{}]{0,400})\}""", block)
    if not m:
        return []
    return [k for k in _OBJ_KEYS.findall("{" + m.group(1) + "}") if not k.startswith("$")][:20]


def extract_js(text, base_url, reg, *, source="js", where=""):
    """JS 한 덩어리에서 경로·메서드·파라미터 후보를 모은다. 모은 수를 돌려준다."""
    before = len(reg)
    host = urlsplit(base_url).netloc
    text = text[:3_000_000]
    called = set()

    def keep(raw):
        p = _clean_path(raw)
        if not p:
            return None
        url = urljoin(base_url, p)
        return url if urlsplit(url).netloc == host else None

    # 1) 호출 — fetch(url, {method, body}), axios.post(url, data), $.ajax({url, type}) …
    for m in _CALL.finditer(text):
        args = _args_after(text, m.end())
        name = m.group(1).lower()
        verb = (m.group(2) or m.group(3) or m.group(4) or "").upper()
        um = re.match(r"""\s*(["'`])(.*?)\1""", args, re.S) or re.search(r"""\burl\s*:\s*(["'`])(.*?)\1""", args)
        if not um:
            continue
        cm = _CONCAT.match(args.lstrip())            # fetch("/a/" + id + "/b")
        url = keep(_concat_raw(cm) if cm else um.group(2))
        if not url:
            continue
        method = verb if verb in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD") else ""
        if not method:
            mm = _METHOD_OPT.search(args)
            method = mm.group(1).upper() if mm else ("POST" if name == "$.post" else "GET")
        params = {}
        for k in _object_keys(args, "params"):
            params[k] = ("query", "")
        body_keys = _object_keys(args, "body") or _object_keys(args, "data")
        if not body_keys and verb in ("POST", "PUT", "PATCH"):
            # axios.post(url, { a, b }) — 두 번째 인자가 본문
            sm = re.match(r"""\s*(["'`]).*?\1\s*,\s*\{([^{}]{0,400})\}""", args, re.S)
            if sm:
                body_keys = [k for k in _OBJ_KEYS.findall("{" + sm.group(2) + "}")][:20]
        for k in body_keys:
            params[k] = ("json", "")
        reg.add(method, url, source, params=params,
                evidence=f"{where or 'JS'} 호출 {m.group(1)}(…) — 메서드 {'선언' if (verb or _METHOD_OPT.search(args)) else '추정'}")
        called.add(urlsplit(url).path)

    # 2) 이어 붙인 경로 "/a/" + id — 조각("/a/", "/b")이 3) 에서 따로 잡히지 않게 자리를 기억한다
    joined = []
    for m in _CONCAT.finditer(text):
        joined.append((m.start(), m.end()))
        url = keep(_concat_raw(m))
        if url and normalize_path(urlsplit(url).path) not in called:
            reg.add("GET", url, source, evidence=f"{where or 'JS'} 문자열 결합 — 메서드 미확인")

    # 3) 나머지 경로 문자열 — 메서드는 모른다(GET 으로 두고 '추정')
    for m in _JS_STR.finditer(text):
        if any(a <= m.start() < b for a, b in joined):
            continue
        url = keep(m.group(2))
        if not url:
            continue
        path = normalize_path(urlsplit(url).path)
        if path in {normalize_path(c) for c in called}:
            continue
        reg.add("GET", url, source, evidence=f"{where or 'JS'} 경로 문자열 — 메서드 미확인")
    return len(reg) - before


def extract_build_manifest(text, base_url, reg):
    """Next.js _buildManifest.js 의 화면 경로 목록. 화면이라 kind=page."""
    n = 0
    for route in set(_BUILD_MANIFEST.findall(text)):
        if route.startswith("/_") or route in ("/404", "/500"):
            continue
        reg.add("GET", urljoin(base_url, route), "manifest", evidence="Next.js _buildManifest 화면 경로", kind="page")
        n += 1
    return n


def sourcemap_url(js_text, js_url):
    m = _SOURCEMAP.search(js_text[-2000:])
    if not m or m.group(1).startswith("data:"):
        return None
    return urljoin(js_url, m.group(1))


def sourcemap_sources(map_text):
    """소스맵에 원본 코드가 들어 있으면 그것을 돌려준다(없으면 빈 목록)."""
    try:
        doc = json.loads(map_text)
    except ValueError:
        return []
    return [s for s in (doc.get("sourcesContent") or []) if isinstance(s, str)][:200]


# ── robots · sitemap ─────────────────────────────────────────

def parse_robots(text, origin, reg):
    """→ 사이트맵 주소 목록. Disallow 는 숨기고 싶은 경로라 근거에 따로 적는다."""
    sitemaps = []
    for line in text.splitlines():
        m = re.match(r"\s*(allow|disallow|sitemap)\s*:\s*(\S+)", line, re.I)
        if not m:
            continue
        kind, val = m.group(1).lower(), m.group(2)
        if kind == "sitemap":
            sitemaps.append(urljoin(origin, val))
            continue
        p = val.split("*")[0].rstrip("$")
        if p and p != "/":
            reg.add("GET", urljoin(origin, p), "meta",
                    evidence="robots.txt Disallow — 숨기고 싶은 경로일 수 있음" if kind == "disallow"
                    else "robots.txt Allow")
    return sitemaps


def parse_sitemap(text, origin, reg, limit=300):
    """→ 하위 사이트맵 주소 목록."""
    if "<urlset" not in text and "<sitemapindex" not in text:
        return []
    locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)
    if "<sitemapindex" in text:
        return locs[:5]
    host = urlsplit(origin).netloc
    for loc in locs[:limit]:
        if urlsplit(loc).netloc == host:
            reg.add("GET", loc, "meta", evidence="sitemap.xml", kind="page")
    return []


# ── API 명세 ────────────────────────────────────────────────

def _ref(doc, obj, depth=0):
    if isinstance(obj, dict) and "$ref" in obj and depth < 5:
        node = doc
        for part in obj["$ref"].lstrip("#/").split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        return _ref(doc, node, depth + 1)
    return obj if isinstance(obj, dict) else {}


def base_candidates(doc, spec_url):
    """명세가 적은 접두사와 **명세를 찾은 자리에서 되찾은 접두사** → 시도할 순서대로.

    명세의 servers 가 늘 맞지는 않는다. 새싹에듀는 `https://sesacedu.store` 라고만 적어 두었는데
    실제 API 는 `/backend` 아래에 있다(11-21 실측). 그걸 그대로 믿어서 모은 주소가 전부 화면
    라우트로 떨어졌고, 점검이 SPA 껍데기만 두드렸다.
    """
    declared = ""
    if doc.get("servers"):
        declared = urlsplit(str(doc["servers"][0].get("url", ""))).path.rstrip("/")
    elif doc.get("basePath"):
        declared = str(doc["basePath"]).rstrip("/")
    path = urlsplit(spec_url).path
    found = ""
    for tail in SPEC_TAILS:
        if path.endswith(tail):
            found = path[:-len(tail)].rstrip("/")
            break
    out = []
    for b in (declared, found, ""):
        if b not in out:
            out.append(b)
    return out


def pick_base(doc, spec_url, origin, get):
    """후보 접두사 중 **실제로 닿는** 것을 고른다 → (접두사, 왜 그렇게 골랐는지).

    get(url) 이 응답을 돌려준다. 첫 화면과 같은 본문이 오면 그 접두사는 화면 라우트라 아니다.
    """
    cands = base_candidates(doc, spec_url)
    if len(cands) == 1:
        return cands[0], ""
    samples = [p for p in list(doc.get("paths") or {}) if "{" not in p][:3]
    if not samples:
        return cands[0], ""
    try:
        shell = get(origin + "/")
        shell_body = shell.body if 200 <= shell.status < 300 else None
    except OSError:
        shell_body = None
    for base in cands:
        for p in samples:
            try:
                r = get(origin + base + p)
            except OSError:
                continue
            if r.status == 404 or (shell_body is not None and r.body == shell_body):
                continue
            why = f"명세 경로가 {base or '/'} 아래에서 응답함({p} → {r.status})"
            if base != cands[0]:
                why += f" — 명세가 적은 {cands[0] or '/'} 는 화면 라우트였다"
            return base, why
    return cands[0], ""


def parse_openapi(doc, spec_url, origin, reg, get=None):
    """OpenAPI 3 / Swagger 2 → 후보 수. 파라미터 위치(query·path·header)와 본문 키까지 읽는다.

    get 을 주면 명세가 적은 접두사를 그대로 믿지 않고 실제로 닿는 것을 골라 쓴다.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return 0
    note = ""
    if get:
        base, note = pick_base(doc, spec_url, origin, get)
    else:
        base = base_candidates(doc, spec_url)[0]
    n = 0
    for path, ops in doc["paths"].items():
        if not isinstance(ops, dict):
            continue
        shared = ops.get("parameters", [])
        for method, op in ops.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                continue
            op = op if isinstance(op, dict) else {}
            params = {}
            for p in shared + op.get("parameters", []):
                p = _ref(doc, p)
                where = {"query": "query", "path": "path", "header": "header", "formData": "form",
                         "body": "json"}.get(p.get("in"), "")
                if where == "json":                       # Swagger 2 의 body 파라미터
                    for k in (_ref(doc, p.get("schema", {})).get("properties") or {}):
                        params[k] = ("json", "")
                elif where and p.get("name"):
                    params[p["name"]] = (where, str(p.get("example", "")))
            content = _ref(doc, op.get("requestBody", {})).get("content", {})
            for ctype, media in content.items():
                props = _ref(doc, media.get("schema", {})).get("properties") or {}
                for k in props:
                    params[k] = ("json" if "json" in ctype else "form", "")
            reg.add(method, urljoin(origin, base + path), "spec", params=params,
                    evidence=f"API 명세 {urlsplit(spec_url).path} — {method.upper()} 선언"
                             + (f". {note}" if note else ""))
            n += 1
    return n


def parse_actuator_mappings(doc, origin, reg):
    """Spring Boot /actuator/mappings → 후보 수. 경로와 메서드가 다 나온다."""
    n = 0

    def walk(node):
        nonlocal n
        if isinstance(node, dict):
            cond = (node.get("details") or {}).get("requestMappingConditions") if isinstance(node.get("details"), dict) else None
            if cond:
                methods = cond.get("methods") or ["GET"]
                for pat in cond.get("patterns") or []:
                    for m in methods:
                        params = {p.get("name"): ("query", "") for p in cond.get("params") or [] if p.get("name")}
                        reg.add(m, urljoin(origin, pat), "spec", params=params,
                                evidence="Spring Actuator /mappings — 인증 없이 열림")
                        n += 1
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(doc)
    return n


def load_json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


# ── 있는지 확인 (soft-404 기준 비교) ─────────────────────────

def fingerprint(resp, token=""):
    body = resp.body.replace(token, "") if token else resp.body
    body = re.sub(r"\d+", "0", body)
    return (resp.status, resp.header("Content-Type").split(";")[0].strip(),
            hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest(), len(body))


def looks_like(fp, baselines):
    for b in baselines:
        if fp[0] != b[0]:
            continue
        if fp[2] == b[2]:
            return True
        if b[3] and fp[1] == b[1] and abs(fp[3] - b[3]) / max(b[3], 1) < 0.03:
            return True
    return False


class Verifier:
    """get(url) → Response 를 받아 후보 상태를 정한다. 기준 응답은 경로 첫 칸마다 한 번 만든다."""

    def __init__(self, get, options=None):
        self.get, self.options = get, options
        self.baselines = {}

    def baseline(self, origin, prefix):
        key = (origin, prefix)
        if key not in self.baselines:
            fps = []
            tok = "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
            try:
                fps.append(fingerprint(self.get(f"{origin}{prefix.rstrip('/')}/{tok}"), tok))
            except OSError:
                pass
            self.baselines[key] = fps
        return self.baselines[key]

    def check(self, c):
        s = urlsplit(c.url)
        origin = f"{s.scheme}://{s.netloc}"
        probe_path = re.sub(r"\{[^}]+\}", "1", c.path)
        url = origin + probe_path
        segs = [x for x in c.path.split("/") if x]
        prefix = "/" + segs[0] if len(segs) > 1 else "/"
        bases = self.baseline(origin, prefix) + (self.baseline(origin, "/") if prefix != "/" else [])
        if c.method not in ("GET", "HEAD") and self.options:
            # 상태를 바꾸지 않으려고 POST 등은 OPTIONS 의 허용 목록으로 먼저 본다
            try:
                r = self.options(url)
                allow = (r.header("Allow") + "," + r.header("Access-Control-Allow-Methods")).upper()
                if r.status < 400 and c.method in allow:
                    c.state, c.status = "exists", r.status
                    c.evidence.append(f"OPTIONS 허용 메서드: {allow.strip(',')}")
                    return
            except OSError:
                pass
        try:
            r = self.get(url)
        except OSError:
            return
        c.status = r.status
        if c.method != "GET":
            c.evidence.append(f"{c.method} 는 보내지 않고 같은 경로 GET 응답({r.status})으로 봄 — 메서드 성공 여부 미확인")
        sc = r.status
        if sc in (404, 410):
            c.state = "not_found" if c.method == "GET" else "unverified"
        elif looks_like(fingerprint(r), bases):
            c.state = "soft_404"
        elif sc in (401, 403):
            c.state = "auth_required"
        elif sc == 405:
            c.state = "method_mismatch"
        elif 300 <= sc < 400:
            loc = r.header("Location").lower()
            c.state = "auth_required" if ("login" in loc or "signin" in loc) else "redirect"
        elif sc >= 500:
            c.state = "server_error"
        elif 200 <= sc < 300 or sc in (400, 422):
            c.state = "exists"


# ── HAR(브라우저·Burp 가 실제로 보낸 요청) ──────────────────────

# 브라우저가 늘 붙이는 헤더는 파라미터가 아니다. 앱이 따로 붙인 헤더(X-…)만 남긴다
_STD_HEADERS = {"host", "connection", "content-length", "content-type", "accept", "accept-encoding",
                "accept-language", "user-agent", "referer", "origin", "cookie", "authorization", "cache-control",
                "pragma", "upgrade-insecure-requests", "if-none-match", "if-modified-since", "dnt", "te", "priority"}


def _observed_state(status):
    if not status:
        return "unverified"
    if status in (401, 403):
        return "auth_required"
    if status in (404, 410):
        return "not_found"
    if status == 405:
        return "method_mismatch"
    if status >= 500:
        return "server_error"
    if 300 <= status < 400:
        return "redirect"
    return "exists"


def parse_har(text, base_url, reg):
    """HAR(JSON) → 후보 수. 대상 호스트의 요청만, 정적 파일은 뺀다.

    쿼리·폼·JSON 본문 키·앱 전용 헤더를 파라미터로 남기고, 응답 코드를 그대로 상태로 쓴다
    (실제로 오간 것이라 다시 확인할 필요가 없다).
    """
    doc = load_json(text)
    if doc is None:
        raise ValueError("HAR 는 JSON 이어야 합니다 — 개발자도구 네트워크 탭의 'HAR 로 저장' 파일 내용을 붙여 넣으세요")
    entries = ((doc.get("log") or {}).get("entries")) if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise ValueError("HAR 에 log.entries 가 없습니다")
    host = urlsplit(base_url).netloc
    n = 0
    for e in entries:
        req = (e or {}).get("request") or {}
        url, method = req.get("url") or "", (req.get("method") or "GET").upper()
        s = urlsplit(url)
        if s.netloc != host or method == "OPTIONS" or STATIC_EXT.search(s.path) or SCRIPT_EXT.search(s.path):
            continue
        params = {}
        post = req.get("postData") or {}
        mime = (post.get("mimeType") or "").lower()
        if "json" in mime:
            body = load_json(post.get("text") or "")
            if isinstance(body, dict):
                for k, v in body.items():
                    params[str(k)] = ("json", v if isinstance(v, (str, int, float)) else "")
        elif post:
            pairs = [(p.get("name"), p.get("value", "")) for p in post.get("params") or []] \
                or parse_qsl(post.get("text") or "", keep_blank_values=True)
            for k, v in pairs:
                if k:
                    params[k] = ("form", v)
        for h in req.get("headers") or []:
            name = (h.get("name") or "").strip()
            low = name.lower()
            if name and not name.startswith(":") and low not in _STD_HEADERS and not low.startswith("sec-"):
                params[name] = ("header", h.get("value", ""))
        status = ((e.get("response") or {}).get("status")) or 0
        c = reg.add(method, url, "har", params={k: (pl, str(v)[:200]) for k, (pl, v) in params.items()},
                    evidence=f"HAR 관찰 — 실제로 오간 요청(응답 {status})")
        c.state, c.status = _observed_state(status), status
        n += 1
    return n


# ── 예측(있을 법한 경로) ─────────────────────────────────────

API_HINTS = {"api", "backend", "rest", "service", "services", "gateway"}
GUESS_WORDS = ["admin", "users", "user", "members", "me", "profile", "config", "settings", "health", "status",
               "info", "version", "debug", "internal", "test", "export", "import", "upload", "download", "files",
               "logs", "metrics", "actuator", "swagger-ui", "api-docs", "search", "report", "reports", "stats"]


def guess(reg, base_url, words=None, limit=150):
    """이미 아는 경로에서 있을 법한 경로를 만든다 → 새 후보 수. 확인 단계에서 걸러진다.

    상위 경로, 목록 → 단건(/{id}), 버전 바꾸기(v1↔v2), API 머리 경로 + 흔한 단어.
    """
    host = urlsplit(base_url).netloc
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(base_url))
    known = [c for c in reg if urlsplit(c.url).netloc == host and c.kind == "api"]
    # 경로 변수 이름은 달라도 같은 자리다 — /courses/{id} 와 /courses/{courseId}
    same = lambda path: re.sub(r"\{[^}/]*\}", "{}", path)
    have = {same(c.path) for c in reg}
    prefixes, cands = set(), []

    def add(path):
        if same(path) not in have and path not in cands:
            have.add(same(path))
            cands.append(path)
    for c in known:
        segs = [x for x in c.path.split("/") if x]
        api = bool(segs) and segs[0].lower() in API_HINTS
        if api:
            prefixes.add("/" + segs[0])
            if len(segs) > 1 and re.fullmatch(r"v\d+", segs[1]):
                prefixes.add("/" + "/".join(segs[:2]))
        for i in range(1, len(segs)):
            add("/" + "/".join(segs[:i]))
        if api and len(segs) >= 2 and not segs[-1].startswith("{"):
            add(c.path.rstrip("/") + "/{id}")
        for i, seg in enumerate(segs):
            m = re.fullmatch(r"v(\d+)", seg)
            if m:
                for v in (int(m.group(1)) - 1, int(m.group(1)) + 1):
                    if v >= 1:
                        add("/" + "/".join(segs[:i] + [f"v{v}"] + segs[i + 1:]))
    for pre in sorted(prefixes):
        for w in words or GUESS_WORDS:
            add(f"{pre}/{w}")
    for path in cands[:limit]:
        reg.add("GET", origin + path, "guess", evidence="예측 후보 — 아는 경로에서 만들어 봄")
    return min(len(cands), limit)


def drop_unconfirmed_guesses(reg):
    """예측으로만 나왔고 있다고 확인되지 않은 후보는 버린다 — 남기면 목록이 추측으로 찬다."""
    for key, c in list(reg.items.items()):
        if c.sources == ["guess"] and c.state in ("unverified", "not_found", "soft_404"):
            del reg.items[key]


# ── 숨은 파라미터 찾기 ───────────────────────────────────────

MINE_WORDS = ["id", "page", "size", "limit", "offset", "sort", "order", "q", "query", "search", "keyword",
              "filter", "type", "category", "lang", "format", "debug", "test", "admin", "mode", "view", "preview",
              "callback", "redirect", "url", "next", "return", "file", "path", "template", "include", "user",
              "userId", "memberId", "role", "status", "from", "to", "date", "fields", "expand", "verbose"]


def mine_params(c, get, words=None, batch=20):
    """GET 엔드포인트 하나에 이름 후보를 묶어 붙여 보내, 응답이 달라지는 이름을 찾는다 → 찾은 수.

    같은 요청을 두 번 보내 응답이 같은지부터 본다(매번 바뀌는 화면이면 비교할 수 없어 그만둔다).
    묶음에서 차이가 나면 하나씩 다시 보내 범인을 고른다. 넣은 값이 응답에 그대로 나오면 '반사' 로 적는다.
    """
    url = re.sub(r"\{[^}]+\}", "1", c.url)
    known = [(k, v) for k, (place, v) in c.params.items() if place == "query"]

    def send(extra):
        q = "&".join(f"{k}={v}" for k, v in known + list(extra.items()))
        return get(url + ("?" + q if q else ""))
    try:
        a, b = send({}), send({})
    except OSError:
        return 0
    base = fingerprint(a)
    if fingerprint(b) != base:
        c.evidence.append("숨은 파라미터 찾기: 같은 요청에도 응답이 매번 달라 비교할 수 없어 건너뜀")
        return 0
    names = [w for w in (words or MINE_WORDS) if w not in c.params]
    found = 0
    for i in range(0, len(names), batch):
        group = names[i:i + batch]
        vals = {n: "zq" + "".join(random.choices(string.ascii_lowercase, k=6)) for n in group}
        try:
            r = send(vals)
        except OSError:
            continue
        if fingerprint(r) == base and not any(v in r.body for v in vals.values()):
            continue
        for n in group:
            try:
                one = send({n: vals[n]})
            except OSError:
                continue
            reflected = vals[n] in one.body
            if reflected or fingerprint(one) != base:
                why = "넣은 값이 응답에 그대로 나옴" if reflected else f"붙이면 응답이 달라짐({a.status}→{one.status})"
                c.params.setdefault(n, ("query", ""))
                if "mine" not in c.sources:
                    c.sources.append("mine")
                c.evidence.append(f"숨은 파라미터 {n} — {why}")
                found += 1
    return found


# ── 위험 점수 ──────────────────────────────────────────────

RISKY_PATH = [
    (r"admin|manage|internal|console", "관리 기능 경로", 15),
    (r"actuator|debug|trace|metrics|env\b|heapdump", "운영·디버그 경로", 20),
    (r"upload|import|attach", "파일 올리기", 15),
    (r"download|file|export|material", "파일 내려받기(경로 조작 후보)", 15),
    (r"login|auth|token|password|reset|signup|register", "인증 흐름", 10),
    (r"user|member|account|profile", "개인 정보", 8),
    (r"pay|order|point|coupon", "결제·포인트", 10),
    (r"graphql", "GraphQL", 15),
    (r"api-docs|swagger|openapi", "API 문서 공개", 10),
]
SSRF_PARAM = re.compile(r"^(url|uri|link|redirect|return|next|callback|dest|target|src|image|feed|host|site)(_?url)?$", re.I)
INJECT_PARAM = re.compile(r"^(q|query|search|keyword|filter|sort|order|orderby|where|name|title|category|type|id)$", re.I)
FILE_PARAM = re.compile(r"^(file|filename|path|dir|folder|doc|template|page|include)$", re.I)
# 이유 → 다음에 해 볼 점검(딸깍이 모듈 이름은 화면에서 붙인다)
SUGGEST = {"SSRF": "SSRF·열린 리다이렉트", "INJECT": "SQL 주입·XSS", "FILE": "경로 조작",
           "IDOR": "남의 데이터 열람(IDOR)", "AUTH": "권한 우회", "ERROR": "에러 처리"}


SUGGEST_LABEL = {"INJECT": "SQL 주입·XSS", "FILE": "경로 조작", "SSRF": "SSRF·열린 리다이렉트",
                 "IDOR": "남의 데이터 열람(IDOR)"}


def suggest(name, place):
    """파라미터 하나에 해 볼 점검 — SUGGEST_LABEL 의 키 목록. 이름과 위치만 본다."""
    out = []
    if SSRF_PARAM.match(name):
        out.append("SSRF")
    if FILE_PARAM.match(name):
        out.append("FILE")
    if place == "path" or re.fullmatch(r"\w*[iI]d", name):
        out.append("IDOR")
    if INJECT_PARAM.match(name) or (place in ("query", "form", "json") and not out):
        out.append("INJECT")             # 값을 넣는 칸이면 기본은 주입 점검
    return out


def score(c):
    if c.kind == "page":
        c.risk, c.reasons = 0, []
        return c
    risk, why = 0, []
    if c.method in ("POST", "PUT", "PATCH", "DELETE"):
        risk += 15
        why.append(f"{c.method} — 상태를 바꾸는 요청")
    low = c.path.lower()
    for rx, label, pts in RISKY_PATH:
        if re.search(rx, low):
            risk += pts
            why.append(label)
    names = list(c.params)
    if any(SSRF_PARAM.match(n) for n in names):
        risk += 20
        why.append("URL·리다이렉트형 파라미터 → " + SUGGEST["SSRF"])
    if any(INJECT_PARAM.match(n) for n in names):
        risk += 10
        why.append("검색·정렬형 파라미터 → " + SUGGEST["INJECT"])
    if any(FILE_PARAM.match(n) for n in names):
        risk += 15
        why.append("파일·경로형 파라미터 → " + SUGGEST["FILE"])
    if any(place == "path" for place, _ in c.params.values()):
        risk += 10
        why.append("경로에 객체 번호 → " + SUGGEST["IDOR"])
    if names:
        risk += min(15, 3 * len(names))
    if c.state == "auth_required":
        risk += 10
        why.append("인증 필요 → " + SUGGEST["AUTH"])
    if c.state == "server_error":
        risk += 10
        why.append("5xx 응답 → " + SUGGEST["ERROR"])
    if c.state == "exists" and re.search(r"admin|internal|debug|actuator|config", low):
        risk += 15
        why.append("인증 없이 관리·설정 경로가 응답")
    if any("Disallow" in e for e in c.evidence):
        risk += 5
        why.append("robots.txt 가 숨긴 경로")
    if not names and c.method == "GET" and len(why) <= 1:
        risk = int(risk * 0.6)            # 넣을 칸도 특이점도 없으면 찔러 볼 가치가 낮다
    if c.state in ("not_found", "soft_404"):
        risk = int(risk * 0.3)
    c.risk, c.reasons = min(100, risk), why
    return c
