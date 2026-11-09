"""연습용 대상의 로그인 — 실서버와 같은 모양으로 토큰을 준다.

여기서 되면 실서버에서도 된다는 것이 이 서버의 쓸모다. 그래서 주소·보내는 모양·
응답 봉투(`{code, message, result}`)를 맞춰 두고, **그게 유지되는지** 를 본다.
계정은 가짜라 가리지 않는다 — 안 보이면 기능을 돌려 볼 수가 없다.
"""
import json

import pytest

import demo_target
from dashboard import login
from dashboard.db import get_db


@pytest.fixture
def demo():
    demo_target.app.config.update(TESTING=True)
    return demo_target.app.test_client()


def post_login(demo, email, pw):
    r = demo.post("/backend/login", json={"email": email, "pw": pw})
    return r.status_code, json.loads(r.get_data(as_text=True))


# ── 봉투와 토큰 자리 ──────────────────────────────────────────────

def test_a_good_account_gets_a_token_under_result(demo):
    """토큰이 result 아래에 온다 — 팩의 token_keys 가 보는 자리다."""
    status, body = post_login(demo, "demo@sesacedu.test", "demo1234")
    assert status == 200 and body["code"] == "SUCCESS"
    assert body["result"]["token"].count(".") == 2


def test_the_dashboard_finds_that_token_with_the_real_pack_keys():
    """실서버 설정 그대로 꺼내진다. 이 둘이 어긋나면 화면에서 '토큰이 없습니다' 가 뜬다."""
    from projects.sesacedu import PROJECT
    body = json.dumps({"code": "SUCCESS", "message": "", "result": {"token": "a.b.c"}})
    assert login.find_token(body, PROJECT["login"]["token_keys"]) == "a.b.c"


def test_a_bearer_prefix_is_stripped():
    """authorizationHeader 자리에는 'Bearer ' 가 붙어 온다. 또 붙이면 두 번이 된다."""
    body = json.dumps({"result": {"authorizationHeader": "Bearer a.b.c"}})
    assert login.find_token(body, ["result.authorizationHeader"]) == "a.b.c"


def test_a_missing_token_says_what_the_response_did_have():
    """어디 있는지 모르면 고칠 수가 없다. 자리 이름만 보여 준다 — 값은 안 보여 준다."""
    body = json.dumps({"code": "SUCCESS", "result": {"userId": 1, "secretThing": "zzz"}})
    with pytest.raises(login.LoginFailed) as e:
        login.find_token(body, ["token"])
    assert "result.userId" in str(e.value)
    assert "zzz" not in str(e.value)        # 값은 절대 새지 않는다


# ── 거절 ──────────────────────────────────────────────────────────

def test_a_wrong_password_is_refused_without_saying_which_part(demo):
    status, body = post_login(demo, "demo@sesacedu.test", "nope")
    assert status == 400 and body["code"] == "LOGIN_FAILED"
    assert "이메일 또는 비밀번호" in body["message"]


def test_an_empty_field_comes_back_like_the_real_server(demo):
    """실측한 실서버 응답과 같은 모양 — {code: INVALID_INPUT, result: {errors: [...]}}."""
    status, body = post_login(demo, "", "")
    assert status == 400 and body["code"] == "INVALID_INPUT"
    assert {e["field"] for e in body["result"]["errors"]} == {"email", "pw"}


# ── 받은 토큰이 실제로 통하는지 ────────────────────────────────────

def test_the_token_works_on_a_protected_path(demo):
    _, body = post_login(demo, "teacher@sesacedu.test", "teach1234")
    r = demo.get("/backend/me", headers={"Authorization": body["result"]["authorizationHeader"]})
    assert r.status_code == 200
    assert json.loads(r.get_data(as_text=True))["result"]["role"] == "INSTRUCTOR"


def test_without_a_header_it_is_401(demo):
    assert demo.get("/backend/me").status_code == 401


# ── 계정이 보여야 돌려 볼 수 있다 ──────────────────────────────────

def test_the_front_page_lists_the_accounts(demo):
    page = demo.get("/").get_data(as_text=True)
    for email, who in demo_target.ACCOUNTS.items():
        assert email in page and who["pw"] in page


def test_the_practice_role_gets_the_account_filled_in(app):
    """연습용 역할에만 넣어 둔다. 실서버 역할은 사람이 자기 계정을 넣는다."""
    with app.app_context():
        pj = app.config["PROJECTS"]["sesacedu"]
        assert login.config_for(pj, "practice")["demo"]["ident"] == "demo@sesacedu.test"
        assert "demo" not in login.config_for(pj, "user_web")


def test_the_form_shows_the_practice_account(app, client):
    client.post("/targets", data={"project": "sesacedu", "role": "practice", "name": "연습",
                                  "url": "http://127.0.0.1:5051"}, follow_redirects=True)
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert 'value="demo@sesacedu.test"' in page
    assert 'value="demo1234"' in page          # 가짜 계정이라 가리지 않는다
    assert "demo@sesacedu.test / demo1234" in page


def test_a_real_target_does_not_get_a_prefilled_password(app, client):
    """실서버 대상에 계정이 미리 들어가 있으면 안 된다."""
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹",
                                  "url": "https://sesacedu.store"}, follow_redirects=True)
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
    page = client.get(f"/targets?target={tid}").get_data(as_text=True)
    assert 'name="secret" type="password"' in page
    assert "demo1234" not in page


def test_token_in_the_authorization_response_header_is_taken(monkeypatch):
    """실서버 /backend/login 은 토큰을 본문이 아니라 응답 헤더 Authorization: Bearer … 로 준다."""
    from dashboard import core
    from projects.sesacedu import PROJECT
    body = json.dumps({"code": "LOGIN_SUCCESS", "message": "", "result": {"member": {"memberId": 1}}})
    monkeypatch.setattr(core, "fetch", lambda *a, **k: core.Response(
        url="https://sesacedu.store/backend/login", status=200,
        headers=[("Authorization", "Bearer a.b.c")], body=body))
    assert login.fetch_token("https://sesacedu.store", PROJECT["login"], "t@sesacedu.test", "pw") == "a.b.c"
