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
