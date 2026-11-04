import pytest

from dashboard import create_app
from dashboard.core import Response


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE": str(tmp_path / "t.sqlite3"),
                       "CSRF": False, "DELAY_MS": 0})


@pytest.fixture(autouse=True)
def _no_leftover_jobs():
    """테스트끼리 백그라운드 기록이 새지 않게."""
    from dashboard import jobs
    jobs.reset()
    yield
    jobs.wait_all(timeout=5)
    jobs.reset()


@pytest.fixture
def client(app):
    """POST 뒤에는 백그라운드 실행이 끝날 때까지 기다린다.

    모듈 실행은 이제 작업자 스레드에서 돈다. 테스트가 바로 결과를 보면 아직
    안 끝났을 수 있다. 동기로 되돌리지 않고 **진짜로 기다린다** — 그래야
    백그라운드 경로가 테스트에서도 실제로 돌아간다.
    """
    from dashboard import jobs
    c = app.test_client()
    post = c.post

    def waiting_post(*a, **kw):
        # follow_redirects 로 보내면 리다이렉트된 화면이 POST 안에서 그려진다.
        # 그때는 작업이 아직 안 끝났다. 사람이 하는 것과 같은 순서로 바꾼다 —
        # 눌러서 돌아오고, 끝나기를 기다렸다가, 그 화면을 다시 연다.
        follow = kw.pop("follow_redirects", False)
        r = post(*a, **kw)
        jobs.wait_all(timeout=10)
        if follow and r.status_code in (301, 302, 303, 307, 308):
            return c.get(r.headers["Location"], follow_redirects=True)
        return r

    c.post = waiting_post
    return c


@pytest.fixture
def fake_fetch():
    """경로별 가짜 응답을 돌려주는 fetch. 없는 경로는 404."""
    def make(pages):
        calls = []

        def fetch(url, **_kw):
            calls.append(url)
            for suffix, resp in pages.items():
                if url.endswith(suffix):
                    return Response(url=url, status=resp.get("status", 200),
                                    headers=resp.get("headers", []), body=resp.get("body", ""))
            return Response(url=url, status=404, headers=[], body="not found")
        fetch.calls = calls
        return fetch
    return make
