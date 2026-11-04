"""점검 범위(scope) 검사. 허용한 호스트에만 요청이 나가게 한다."""
from urllib.parse import urlsplit

from flask import current_app, g


class OutOfScope(Exception):
    """허용 범위 밖 대상에 요청하려 할 때."""


def host_of(url: str) -> str:
    return host_port_of(url)[0]


def host_port_of(url: str):
    """(호스트, 포트). 포트를 안 적었으면 http 80 / https 443 으로 본다."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"http/https 주소가 아닙니다: {url}")
    return parts.hostname.lower(), parts.port or (443 if parts.scheme == "https" else 80)


def _host_matches(host: str, entry: str) -> bool:
    """범위 한 줄의 호스트 부분과 맞는지.

    `sesacedu.store`   그 호스트와 하위 도메인까지 (admin.sesacedu.store 포함)
    `=sesacedu.store`  그 호스트만 — 하위 도메인은 제외
    프로젝트 전체 범위는 넓게(하위 도메인 포함), 역할 범위는 `=` 로 좁혀 쓴다.
    사용자 웹 대상으로 돌린 모듈이 관리자 하위 도메인으로 나가지 못하게 하기 위해서다.
    """
    if entry.startswith("="):
        return host == entry[1:]
    return host == entry or host.endswith("." + entry)


def _matches(host: str, port: int, entry: str) -> bool:
    """범위 한 줄과 맞는지. 포트를 안 적으면 포트를 가리지 않고,
    'localhost:3000' 은 그 포트만 허용한다(터널로 여러 서버를 같은 호스트에 열기 때문)."""
    entry = entry.strip().lower()
    head, sep, tail = entry.rpartition(":")
    if sep and tail.isdigit():
        entry, want_port = head, int(tail)
    else:
        want_port = None
    return _host_matches(host, entry) and (want_port is None or port == want_port)


def is_in_scope(url: str, entries) -> bool:
    host, port = host_port_of(url)
    return any(_matches(host, port, e) for e in entries)


LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def is_self(url: str, self_port) -> bool:
    """대시보드 자신을 가리키는 주소인가. 자기 폼을 점검하면 실행·삭제가 실제로 일어난다."""
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return bool(self_port) and host_of(url) in LOOPBACK and port == int(self_port)


def hosts_of(entries):
    """범위 줄들에서 호스트만 뽑는다. 포트 스캔처럼 포트를 가리면 안 되는 일에 쓴다."""
    out = []
    for e in entries:
        head, sep, tail = e.strip().lower().rpartition(":")
        out.append(head if sep and tail.isdigit() else e.strip().lower())
    return out


def ensure_host_allowed(host: str, hosts=None) -> None:
    """포트를 따지지 않는 검사 — 호스트가 프로젝트 범위 안인지만 본다.

    포트 스캔은 '모르는 포트를 찾는 일'이라 역할의 포트 제한을 쓸 수 없다.
    대신 호스트는 반드시 프로젝트가 적어 둔 곳이어야 한다.
    """
    host = (host or "").strip().lower()
    allowed = hosts_of(hosts if hosts is not None
                       else (g.get("host_scope") or current_app.config["SCOPE_HOSTS"]))
    if not any(_host_matches(host, h) for h in allowed):
        raise OutOfScope(f"허용 범위 밖 호스트입니다: {host} (허용: {', '.join(allowed)})")


def ensure_in_scope(url: str, hosts=None) -> None:
    if hosts is None:
        # 모듈 실행 중이면 그 대상 프로젝트의 범위, 아니면 범용 범위
        hosts = g.get("scope_hosts") or current_app.config["SCOPE_HOSTS"]
    if not is_in_scope(url, hosts):
        host, port = host_port_of(url)
        raise OutOfScope(f"허용 범위 밖입니다: {host}:{port} (허용: {', '.join(hosts)})")
    if is_self(url, current_app.config.get("SELF_PORT")):
        raise OutOfScope("대시보드 자신은 점검할 수 없습니다. 연습용 대상(demo_target)을 쓰세요")
