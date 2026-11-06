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


def test_header_line():
    assert login.header_line(CFG, "zzz") == "Authorization: Bearer zzz"


# ── 어느 대상에 보일지 ────────────────────────────────────────────

def test_only_for_the_roles_that_have_a_login(app):
    with app.app_context():
        pj = app.config["PROJECTS"]["sesacedu"]
        assert login.config_for(pj, "user_web")
        assert login.config_for(app.config["PROJECTS"]["general"], "") is None


# ── 역할마다 로그인 모양이 다를 때 ────────────────────────────────
# 새싹에듀는 사용자 API(EC2 ①, SesacEdu_Server)와 관리자 API(EC2 ②, SesacEdu_Admin_Server)가
# **다른 앱**이다. 경로·본문 키·토큰이 오는 자리가 전부 다르다(11-06 저장소 대조).

def test_admin_role_brings_its_own_login_shape(app):
    """관리자 역할은 자기 설정을 들고 있다. roles 목록에 또 적지 않아도 켜진다."""
    with app.app_context():
        cfg = login.config_for(app.config["PROJECTS"]["sesacedu"], "admin_web")
    assert cfg
    # 바깥에서 칠 주소는 Next.js 가 /api/* 를 ②:8080 으로 넘겨 주는 길이다.
    # Spring 핸들러 자체(POST /admin/login)는 ② 안에서만 유효하다.
    assert cfg["path"] == "/api/admin/login"
    assert cfg["json"] == {"id": "{id}", "pw": "{secret}"}      # 사용자 쪽은 email, 관리자는 id
    assert cfg["token_header"] == ""                            # 관리자는 본문으로 준다
    assert "token" in cfg["token_keys"]


def test_admin_login_inherits_what_it_does_not_override(app):
    """적은 것만 덮는다 — 같은 값을 두 번 쓰지 않게."""
    with app.app_context():
        cfg = login.config_for(app.config["PROJECTS"]["sesacedu"], "admin_web")
    assert cfg["header"] == "Authorization" and cfg["prefix"] == "Bearer "
    assert cfg["id_label"] == "관리자 이메일"                     # 이건 덮었다


def test_user_role_still_reads_the_token_from_the_response_header(app):
    """사용자 API 는 토큰을 응답 헤더로 준다 — 11-06 실서버 실측."""
    with app.app_context():
        cfg = login.config_for(app.config["PROJECTS"]["sesacedu"], "user_web")
    assert cfg["token_header"] == "Authorization" and cfg["path"] == "/backend/login"


def test_role_login_survives_the_registry(app):
    """_norm_roles 가 역할에서 모르는 열쇠를 버린다 — login 이 거기서 조용히 사라지면 안 된다."""
    with app.app_context():
        roles = app.config["PROJECTS"]["sesacedu"].roles
    assert roles["admin_web"]["login"]["path"] == "/api/admin/login"
    assert roles["user_web"]["login"] is None               # 역할 설정이 없으면 프로젝트 기본값을 쓴다


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


def test_the_whole_token_is_shown(app, client, monkeypatch):
    """토큰을 가리지 않는다. 자체 실습 환경이고 받자마자 복사해 쓰는 일이 많다."""
    add_target(client)
    tid = only_target(app)
    _fake_login(monkeypatch, body='{"token": "abcdefghijklmnopqrstu"}')
    page = client.post(f"/targets/{tid}/login", data={"ident": "a@b.test", "secret": "pw"},
                       follow_redirects=True).get_data(as_text=True)
    assert "Authorization: Bearer abcdefghijklmnopqrstu" in page


def test_the_header_box_is_prefilled(app, client, monkeypatch):
    """편집 칸에 지금 값이 들어 있어야 한다 — 확인·복사도 되고, 모르고 지우는 일도 없다."""
    add_target(client)
    tid = only_target(app)
    _fake_login(monkeypatch, body='{"token": "tok.en.value"}')
    client.post(f"/targets/{tid}/login", data={"ident": "a", "secret": "b"}, follow_redirects=True)
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert "Authorization: Bearer tok.en.value</textarea>" in page


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


# ── 토큰을 어디서 읽는가 ──────────────────────────────────────────

def _login_with(monkeypatch, headers, body):
    def fetch(url, **_kw):
        return Response(url=url, status=200, headers=headers, body=body)
    monkeypatch.setattr(login.core, "fetch", fetch)


ADMIN_CFG = {"path": "/api/admin/login", "json": {"id": "{id}", "pw": "{secret}"},
             "token_keys": ["token", "authorizationHeader"], "token_header": "",
             "header": "Authorization", "prefix": "Bearer "}


def test_empty_token_header_means_read_the_body(monkeypatch):
    """관리자 API 는 본문으로 준다. 응답에 Authorization 이 섞여 있어도 본문을 봐야 한다."""
    _login_with(monkeypatch, [("Authorization", "Bearer 엉뚱한값")], '{"token": "admin.tok.en"}')
    assert login.fetch_token("https://admin.sesacedu.store", ADMIN_CFG, "a@b.test", "pw") == "admin.tok.en"


def test_token_header_is_read_when_the_pack_says_so(monkeypatch):
    """사용자 API 는 헤더로 준다 — 본문에는 토큰이 없다."""
    cfg = {**CFG, "token_header": "Authorization"}
    _login_with(monkeypatch, [("Authorization", "Bearer user.tok.en")], '{"result": {"member": {}}}')
    assert login.fetch_token("https://sesacedu.store", cfg, "a@b.test", "pw") == "user.tok.en"


def test_admin_token_can_come_from_authorization_header_field(monkeypatch):
    """관리자 응답은 token 과 authorizationHeader 를 같이 준다. 'Bearer ' 는 떼고 넣는다."""
    _login_with(monkeypatch, [], '{"authorizationHeader": "Bearer only.here"}')
    assert login.fetch_token("https://admin.sesacedu.store", ADMIN_CFG, "a", "b") == "only.here"


def test_the_admin_form_shows_the_admin_address(app, client):
    """관리자 대상에도 칸이 뜨고, 어디로 보내는지 적힌다."""
    add_target(client, url="https://admin.sesacedu.store", role="admin_web")
    tid = only_target(app)
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert "로그인해서 토큰 받기" in page
    assert "POST /api/admin/login" in page
    assert "관리자 이메일" in page
