import pytest

from dashboard import create_app
from dashboard.core import Response


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE": str(tmp_path / "t.sqlite3")})


@pytest.fixture
def client(app):
    return app.test_client()


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
