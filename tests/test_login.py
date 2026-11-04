"""로그인해서 토큰 받기.

손으로 curl 치고 응답에서 토큰을 꺼내 붙여 넣던 것을 화면에서 한다.
가장 중요한 것은 **비밀번호가 어디에도 안 남는 것**이다.
"""
import json

import pytest

from dashboard import login
from dashboard.core import Response
from dashboard.db import get_db

CFG = {"path": "/backend/login", "json": {"email": "{id}", "pw": "{secret}"},
       "token_keys": ["token", "data.token"], "header": "Authorization", "prefix": "Bearer ",
       "roles": ["user_web"]}


def add_target(client, url="https://sesacedu.store", role="user_web"):
    return client.post("/targets", data={"project": "sesacedu", "role": role, "name": "웹", "url": url},
                       follow_redirects=True)


def only_target(app):
    with app.app_context():
        return get_db().execute("SELECT id FROM targets").fetchone()["id"]


# ── 응답에서 토큰 찾기 ────────────────────────────────────────────

def test_finds_a_token_at_the_top():
    assert login.find_token('{"token": "abc.def.ghi"}', ["token"]) == "abc.def.ghi"


def test_finds_a_nested_token():
    assert login.find_token('{"data": {"token": "zzz"}}', ["token", "data.token"]) == "zzz"


def test_says_where_it_looked():
    with pytest.raises(login.LoginFailed, match="data.token"):
        login.find_token('{"ok": true}', ["token", "data.token"])


def test_non_json_says_check_the_address():
    with pytest.raises(login.LoginFailed, match="주소"):
        login.find_token("<html>not json</html>", ["token"])


def test_mask_shows_just_enough():
    assert login.mask("abcdefghijklmnopqrstu") == "abcdef…rstu"
    assert login.mask("short") == "…"


def test_header_line():
    assert login.header_line(CFG, "zzz") == "Authorization: Bearer zzz"


# ── 어느 대상에 보일지 ────────────────────────────────────────────

def test_only_for_the_roles_that_have_a_login(app):
    with app.app_context():
        pj = app.config["PROJECTS"]["sesacedu"]
        assert login.config_for(pj, "user_web")
        assert login.config_for(pj, "admin_web") is None     # 관리자 웹은 로그인 모양이 다르다
        assert login.config_for(app.config["PROJECTS"]["general"], "") is None


# ── 실제로 받아서 넣기 ────────────────────────────────────────────

def _fake_login(monkeypatch, status=200, body='{"token": "tok.en.value"}'):
    """로그인 응답을 흉내 내고, 보낸 것을 들여다볼 수 있게 한다."""
    sent = {}

    def fetch(url, **kw):
        sent.update(kw, url=url)
        return Response(url=url, status=status, headers=[], body=body)

    monkeypatch.setattr(login.core, "fetch", fetch)
    return sent


def test_token_goes_into_the_auth_header(app, client, monkeypatch):
    add_target(client)
    tid = only_target(app)
    sent = _fake_login(monkeypatch)
    page = client.post(f"/targets/{tid}/login", data={"ident": "a@b.test", "secret": "pw"},
                       follow_redirects=True).get_data(as_text=True)
    assert "로그인했습니다" in page
    with app.app_context():
        hdrs = get_db().execute("SELECT headers FROM targets WHERE id = ?", [tid]).fetchone()[0]
    assert hdrs.strip() == "Authorization: Bearer tok.en.value"
    assert sent["url"].endswith("/backend/login")


def test_the_password_is_not_recorded(app, client, monkeypatch):
    """요청 기록에 비밀번호가 남으면 안 된다."""
    add_target(client)
    tid = only_target(app)
    sent = _fake_login(monkeypatch)
    client.post(f"/targets/{tid}/login", data={"ident": "a@b.test", "secret": "hunter2"},
                follow_redirects=True)
    assert sent["record_request"] is False       # 보낸 본문을 안 남긴다
    assert sent["record_body"] is False          # 응답에 토큰이 들어 있다


def test_the_password_is_not_stored(app, client, monkeypatch):
    add_target(client)
    tid = only_target(app)
    _fake_login(monkeypatch)
    client.post(f"/targets/{tid}/login", data={"ident": "a@b.test", "secret": "hunter2"},
                follow_redirects=True)
    with app.app_context():
        rows = get_db().execute("SELECT * FROM targets").fetchall()
    assert not any("hunter2" in str(tuple(r)) for r in rows)


def test_only_the_masked_token_is_shown(app, client, monkeypatch):
    add_target(client)
    tid = only_target(app)
    _fake_login(monkeypatch, body='{"token": "abcdefghijklmnopqrstu"}')
    page = client.post(f"/targets/{tid}/login", data={"ident": "a@b.test", "secret": "pw"},
                       follow_redirects=True).get_data(as_text=True)
    assert "abcdef…rstu" in page
    # 전체 토큰은 안내문에 안 쓴다 — 화면 캡처·발표에 그대로 나가면 안 된다
    import re
    flash = " ".join(re.findall(r'class="flash[^"]*">(.*?)<', page, re.S))
    assert "abcdefghijklmnopqrstu" not in flash


def test_other_headers_are_kept(app, client, monkeypatch):
    add_target(client)
    tid = only_target(app)
    client.post(f"/targets/{tid}/headers", data={"headers": "Cookie: SID=x"}, follow_redirects=True)
    _fake_login(monkeypatch)
    client.post(f"/targets/{tid}/login", data={"ident": "a@b.test", "secret": "pw"},
                follow_redirects=True)
    with app.app_context():
        hdrs = get_db().execute("SELECT headers FROM targets WHERE id = ?", [tid]).fetchone()[0]
    assert "Cookie: SID=x" in hdrs and "Authorization: Bearer" in hdrs


def test_a_second_login_replaces_the_old_token(app, client, monkeypatch):
    add_target(client)
    tid = only_target(app)
    _fake_login(monkeypatch, body='{"token": "first"}')
    client.post(f"/targets/{tid}/login", data={"ident": "a", "secret": "b"}, follow_redirects=True)
    _fake_login(monkeypatch, body='{"token": "second"}')
    client.post(f"/targets/{tid}/login", data={"ident": "a", "secret": "b"}, follow_redirects=True)
    with app.app_context():
        hdrs = get_db().execute("SELECT headers FROM targets WHERE id = ?", [tid]).fetchone()[0]
    assert "second" in hdrs and "first" not in hdrs


def test_rejected_login_says_so(app, client, monkeypatch):
    add_target(client)
    tid = only_target(app)
    _fake_login(monkeypatch, status=401, body='{"message": "bad"}')
    page = client.post(f"/targets/{tid}/login", data={"ident": "a", "secret": "b"},
                       follow_redirects=True).get_data(as_text=True)
    assert "거절" in page and "401" in page


def test_empty_fields_are_refused(app, client, monkeypatch):
    add_target(client)
    tid = only_target(app)
    _fake_login(monkeypatch)
    page = client.post(f"/targets/{tid}/login", data={"ident": "", "secret": ""},
                       follow_redirects=True).get_data(as_text=True)
    assert "모두 넣어" in page


def test_the_form_shows_up_for_the_right_target(app, client):
    add_target(client)
    tid = only_target(app)
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert "로그인해서 토큰 받기" in page
    assert "POST /backend/login" in page
