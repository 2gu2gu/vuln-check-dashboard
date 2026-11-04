import pytest

from dashboard import core, scope

HOSTS = ["sesacedu.store", "127.0.0.1"]


@pytest.mark.parametrize("url", [
    "https://sesacedu.store", "https://www.sesacedu.store/a", "http://127.0.0.1:18080/manager",
])
def test_in_scope(url):
    assert scope.is_in_scope(url, HOSTS)


@pytest.mark.parametrize("url", [
    "https://evil-sesacedu.store", "https://sesacedu.store.evil.com", "https://example.com",
    "http://127.0.0.2",
])
def test_out_of_scope(url):
    assert not scope.is_in_scope(url, HOSTS)


def test_rejects_non_http():
    with pytest.raises(ValueError):
        scope.is_in_scope("file:///etc/passwd", HOSTS)


def test_fetch_blocks_before_sending(app, monkeypatch):
    sent = []
    monkeypatch.setattr(core._opener, "open", lambda *a, **k: sent.append(a))
    with app.app_context():
        with pytest.raises(scope.OutOfScope):
            core.fetch("https://example.com/")
    assert sent == []


# ── '=' 는 그 호스트만 (하위 도메인 제외) ──────────────────────────
# 관리자 웹이 8443 포트에서 admin.sesacedu.store 로 옮겨 가면서,
# 역할 범위 'sesacedu.store' 가 관리자 하위 도메인까지 덮는 문제가 생겼다.

def test_bare_entry_still_covers_subdomains():
    assert scope.is_in_scope("https://admin.sesacedu.store/", ["sesacedu.store"])


def test_exact_entry_excludes_subdomains():
    assert scope.is_in_scope("https://sesacedu.store/", ["=sesacedu.store"])
    assert not scope.is_in_scope("https://admin.sesacedu.store/", ["=sesacedu.store"])


def test_user_web_role_cannot_reach_admin_host():
    from dashboard.registry import discover_projects
    projects = discover_projects()[0]
    roles = projects["sesacedu"].roles
    assert not scope.is_in_scope("https://admin.sesacedu.store/", roles["user_web"]["scope"])
    assert scope.is_in_scope("https://admin.sesacedu.store/", roles["admin_web"]["scope"])
    # 터널도 아직 살아 있다
    assert scope.is_in_scope("http://localhost:3000/", roles["admin_web"]["scope"])


def test_exact_entry_with_port():
    assert scope.is_in_scope("http://localhost:3000/", ["=localhost:3000"])
    assert not scope.is_in_scope("http://localhost:8443/", ["=localhost:3000"])


def test_host_scan_respects_exact_entry():
    from dashboard.scope import ensure_host_allowed, OutOfScope
    ensure_host_allowed("sesacedu.store", ["=sesacedu.store"])
    with pytest.raises(OutOfScope):
        ensure_host_allowed("admin.sesacedu.store", ["=sesacedu.store"])
