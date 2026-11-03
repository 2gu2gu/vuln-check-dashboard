"""모듈이 쓰는 공통 자료형과 HTTP 요청 함수."""
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

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

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"verdict 는 {tuple(VERDICTS)} 중 하나: {self.verdict}")


@dataclass
class Response:
    url: str
    status: int
    headers: list = field(default_factory=list)  # [(이름, 값)] — Set-Cookie 처럼 여러 개인 헤더 보존
    body: str = ""

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


def fetch(url: str, *, method: str = "GET", headers=None, data=None, timeout: float = 10,
          max_bytes: int = 1_000_000) -> Response:
    """범위 검사를 거친 뒤 요청한다. 모든 모듈은 이 함수로만 요청한다. data(dict)는 폼 본문."""
    scope.ensure_in_scope(url)
    hdrs = {"User-Agent": "vuln-check-dashboard/0.1", **(headers or {})}
    body = None
    if data is not None:
        body = urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        resp = _opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:  # 3xx·4xx·5xx 도 응답으로 다룬다
        resp = e
    with resp:
        raw = resp.read(max_bytes)
        charset = resp.headers.get_content_charset() or "utf-8"
        return Response(
            url=url,
            status=resp.status if hasattr(resp, "status") else resp.code,
            headers=list(resp.headers.items()),
            body=raw.decode(charset, errors="replace"),
        )


def now_iso() -> str:
    return datetime.now(KST).isoformat(timespec="seconds")


def fmt_kst(iso: str) -> str:
    if not iso:
        return ""
    return datetime.fromisoformat(iso).astimezone(KST).strftime("%m-%d %H:%M")
