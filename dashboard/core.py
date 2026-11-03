"""모듈이 쓰는 공통 자료형과 HTTP 요청 함수."""
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

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


def fetch(url: str, *, method: str = "GET", headers=None, timeout: float = 10,
          max_bytes: int = 1_000_000) -> Response:
    """범위 검사를 거친 뒤 요청한다. 모든 모듈은 이 함수로만 요청한다."""
    scope.ensure_in_scope(url)
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "vuln-check-dashboard/0.1",
        **(headers or {}),
    })
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
