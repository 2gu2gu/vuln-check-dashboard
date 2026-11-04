"""모듈이 쓰는 공통 자료형과 HTTP 요청 함수."""
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

from flask import g, has_app_context

from . import scope

KST = timezone(timedelta(hours=9))

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


@dataclass
class Target:
    id: int
    name: str
    url: str


@dataclass
class Finding:
    title: str
    severity: str
    location: str = ""
    evidence: str = ""
    recommendation: str = ""
    technique: str = ""
    response: object = field(default=None, repr=False, compare=False)  # 근거 응답 — 넣으면 요청 기록과 이어진다

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"알 수 없는 심각도: {self.severity}")


PLACES = ("path", "query", "form")  # 엔드포인트만 / URL 쿼리 / POST 폼 본문


@dataclass
class Point:
    """표면 수집 모듈이 돌려주는 공격 지점 하나."""
    method: str              # GET / POST
    url: str                 # 쿼리를 뺀 절대 주소
    param: str = ""          # 비면 엔드포인트만
    place: str = "path"      # path / query / form
    sample: str = ""         # 발견 당시 값 — 같은 요청의 다른 파라미터를 채울 때 쓴다
    source: str = ""         # link / form / js / import
    id: int = 0              # 저장된 뒤 채워진다
    fields: dict = field(default_factory=dict)  # 점검 때 같은 요청의 파라미터 전부(앱이 채움)

    def __post_init__(self):
        self.method = self.method.upper()
        if self.place not in PLACES:
            raise ValueError(f"place 는 {PLACES} 중 하나: {self.place}")


VERDICTS = {"vuln": "취약", "potential": "잠재", "safe": "안전"}


@dataclass
class Check:
    """지점 점검 모듈이 지점마다 돌려주는 판정."""
    point: Point
    verdict: str             # vuln / potential / safe
    evidence: str = ""
    title: str = ""          # 취약일 때 결과 제목(비면 모듈 이름)
    severity: str = ""       # 취약일 때 심각도(비면 META severity)
    recommendation: str = ""
    response: object = field(default=None, repr=False, compare=False)  # 판정에 쓴 응답

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"verdict 는 {tuple(VERDICTS)} 중 하나: {self.verdict}")


@dataclass
class ToolResult:
    """도구 모듈(stage="tool")이 돌려주는 것. 화면에 바로 보여 준다.

    columns/rows 는 표. 각 행에 drill 을 달면 '이어서 조회' 링크가 생긴다
    (예: 테이블 목록의 한 행 → 그 테이블의 컬럼 보기).
    """
    summary: str = ""
    columns: list = field(default_factory=list)
    rows: list = field(default_factory=list)          # [[값, ...], ...]
    drills: list = field(default_factory=list)        # 행마다 {라벨: {파라미터}} 또는 None
    text: str = ""                                    # 표가 아닌 결과(파일 내용 등)
    findings: list = field(default_factory=list)      # 결과 탭에도 남길 것
    note: str = ""                                    # 화면 아래 주의 문구
    more: dict = field(default_factory=dict)          # 있으면 '다음 N개' 단추가 생긴다
    points: list = field(default_factory=list)        # 표면에도 쌓을 지점


@dataclass
class Response:
    url: str
    status: int
    headers: list = field(default_factory=list)  # [(이름, 값)] — Set-Cookie 처럼 여러 개인 헤더 보존
    body: str = ""
    exchange_id: int = 0  # 요청 기록 번호(실행 중일 때만)

    def header(self, name: str, default: str = "") -> str:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return default

    def header_all(self, name: str) -> list:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # 리다이렉트로 범위 밖 주소에 따라가지 않도록 자동 이동을 끈다.
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)

USER_AGENT = "ddalkkak-dast/0.2"      # 점검 로그에서 우리 요청을 가려내려고 이름을 밝힌다
SECRET_HEADERS = {"cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
BODY_LIMIT = 200_000  # 요청 기록에 남기는 응답 본문 최대 글자 수


class BudgetExceeded(Exception):
    """한 실행에서 보낼 수 있는 요청 수를 넘었을 때."""


class RunContext:
    """모듈 실행 하나의 요청 설정. 앱이 만들어 flask.g.run_ctx 에 둔다."""

    def __init__(self, target_url="", auth_headers=None, delay_ms=0, max_requests=0, recorder=None, cache=None,
                 stop_check=None):
        self.netloc = urlsplit(target_url).netloc
        self.auth_headers = auth_headers or {}
        self.delay = delay_ms / 1000
        self.max_requests = max_requests
        self.recorder = recorder  # (dict) -> 기록 번호
        self.count = 0
        self.cache = cache if cache is not None else {}
        # 백그라운드 실행에서 '멈춤' 을 누르면 이 함수가 예외를 던진다.
        # **보내기 직전에** 본다 — 이미 나간 요청은 서버에 닿았으니 되돌릴 수 없다.
        self.stop_check = stop_check

    def before_send(self):
        if self.stop_check:
            self.stop_check()
        self.count += 1
        if self.max_requests and self.count > self.max_requests:
            raise BudgetExceeded(f"요청 수 한도({self.max_requests})를 넘어 멈췄습니다")
        if self.delay and self.count > 1:
            time.sleep(self.delay)


def _run_ctx():
    return g.get("run_ctx") if has_app_context() else None


def run_cache():
    """모듈이 한 번 읽은 값을 기억해 두는 고—대상·모듈별로 앱이 저장한다."""
    ctx = _run_ctx()
    return ctx.cache if ctx else {}


def redact(headers, injected=()):
    """기록용 헤더. 인증 값은 가리고 이름만 남긴다."""
    out = []
    for k, v in headers:
        low = k.lower()
        if low in injected:
            v = "***(대상 인증 헤더)"
        elif low in SECRET_HEADERS:
            v = "***"
        elif low == "set-cookie":
            v = v.split("=", 1)[0] + "=***" + ("; " + v.split(";", 1)[1].strip() if ";" in v else "")
        out.append((k, v))
    return out


def join(base: str, path: str) -> str:
    """대상 주소 + 경로. 경로가 / 로 시작하지 않아도 붙는다."""
    return base.rstrip("/") + "/" + (path or "").lstrip("/")


def fetch(url: str, *, method: str = "GET", headers=None, data=None, timeout: float = 10,
          max_bytes: int = 1_000_000, record_body: bool = True, record_request: bool = True,
          raw_body: bytes = None, content_type: str = "") -> Response:
    """범위 검사를 거친 뒤 요청한다. 모든 모듈은 이 함수로만 요청한다.

    data(dict)는 폼 본문, raw_body 는 그대로 보낼 바이트(JSON 등).
    record_body=False 면 요청 기록에 응답 본문을 남기지 않는다(.env 처럼 비밀이 섞일 응답).
    record_request=False 면 **보낸 본문**을 남기지 않는다 — 로그인처럼 비밀번호가 실리는 요청.
    실행 중이면 요청 간격·요청 수 한도를 지키고, 대상 인증 헤더를 그 대상 주소에만 붙이고, 요청·응답을 기록한다.
    """
    scope.ensure_in_scope(url)
    ctx = _run_ctx()
    if ctx:
        ctx.before_send()
    hdrs = {"User-Agent": USER_AGENT}
    injected = set()
    if ctx and urlsplit(url).netloc == ctx.netloc:
        hdrs.update(ctx.auth_headers)
        injected = {k.lower() for k in ctx.auth_headers}
    hdrs.update(headers or {})
    body = None
    if raw_body is not None:
        body = raw_body
        hdrs.setdefault("Content-Type", content_type or "application/json")
    elif data is not None:
        body = urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    record = {"method": method, "url": url, "req_headers": redact(list(hdrs.items()), injected),
              "req_body": (body.decode(errors="replace") if body else "") if record_request
                          else "(비밀번호가 실린 요청이라 본문을 남기지 않음)"}
    start = time.monotonic()
    try:
        try:
            resp = _opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:  # 3xx·4xx·5xx 도 응답으로 다룬다
            resp = e
        with resp:
            raw = resp.read(max_bytes)
            charset = resp.headers.get_content_charset() or "utf-8"
            r = Response(url=url, status=resp.status if hasattr(resp, "status") else resp.code,
                         headers=list(resp.headers.items()), body=raw.decode(charset, errors="replace"))
    except OSError as e:
        if ctx and ctx.recorder:
            ctx.recorder({**record, "status": 0, "error": str(e), "ms": int((time.monotonic() - start) * 1000)})
        raise
    if ctx and ctx.recorder:
        r.exchange_id = ctx.recorder({
            **record, "status": r.status, "resp_headers": redact(r.headers), "size": len(r.body),
            "resp_body": r.body[:BODY_LIMIT] if record_body else "(모듈이 민감 응답으로 표시해 본문을 남기지 않음)",
            "ms": int((time.monotonic() - start) * 1000)})
    return r


def now_iso() -> str:
    return datetime.now(KST).isoformat(timespec="seconds")


def fmt_kst(iso: str) -> str:
    if not iso:
        return ""
    return datetime.fromisoformat(iso).astimezone(KST).strftime("%m-%d %H:%M")


def tcp_check(host: str, port: int, timeout: float = 2.0) -> str:
    """포트가 열려 있는지 TCP 연결만 해 본다 — 열림 / 닫힘 / 응답없음.

    보내는 것은 연결 요청뿐이고 바로 끊는다. 데이터를 주고받지 않는다.
    호스트는 프로젝트 범위 안이어야 하고, 요청 간격·한도는 HTTP 와 같이 지킨다.
    """
    scope.ensure_host_allowed(host)
    ctx = _run_ctx()
    if ctx:
        ctx.before_send()
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result = "open"
    except (socket.timeout, TimeoutError):
        result = "filtered"
    except OSError:
        result = "closed"
    ms = int((time.monotonic() - start) * 1000)
    if ctx and ctx.recorder:
        ctx.recorder({"method": "TCP", "url": f"tcp://{host}:{port}", "req_headers": [], "req_body": "",
                      "status": 0, "resp_headers": [], "resp_body": result, "size": 0, "ms": ms,
                      "error": "" if result == "open" else result})
    return result
