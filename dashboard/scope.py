"""점검 범위(scope) 검사. 허용한 호스트에만 요청이 나가게 한다."""
from urllib.parse import urlsplit

from flask import current_app, g


class OutOfScope(Exception):
    """허용 범위 밖 대상에 요청하려 할 때."""


def host_of(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"http/https 주소가 아닙니다: {url}")
    return parts.hostname.lower()


def is_in_scope(url: str, hosts) -> bool:
    host = host_of(url)
    return any(host == h or host.endswith("." + h) for h in hosts)


def ensure_in_scope(url: str, hosts=None) -> None:
    if hosts is None:
        # 모듈 실행 중이면 그 대상 프로젝트의 범위, 아니면 범용 범위
        hosts = g.get("scope_hosts") or current_app.config["SCOPE_HOSTS"]
    if not is_in_scope(url, hosts):
        raise OutOfScope(f"허용 범위 밖입니다: {host_of(url)} (허용: {', '.join(hosts)})")
