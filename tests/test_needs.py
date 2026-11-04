"""실행 전에 준비해야 하는 것(needs) — 화면에 보이고, 없으면 실행을 막는다."""
import pytest

from dashboard import needs
from dashboard.db import get_db


def add_target(client, name="사용자 웹", url="https://sesacedu.store", role="user_web"):
    return client.post("/targets", data={"project": "sesacedu", "role": role, "name": name, "url": url},
                       follow_redirects=True).get_data(as_text=True)


def only_target(app):
    with app.app_context():
        return get_db().execute("SELECT id FROM targets").fetchone()["id"]


# ── META 검사 ─────────────────────────────────────────────────

def test_validate_rejects_unknown_kind():
    with pytest.raises(ValueError, match="kind"):
        needs.validate([{"kind": "магия", "why": "a", "how": "b"}])


def test_validate_requires_why_and_how():
    with pytest.raises(ValueError, match="why"):
        needs.validate([{"kind": "env", "name": "X", "why": "", "how": "b"}])


def test_validate_requires_name_for_checkable_kinds():
    with pytest.raises(ValueError, match="name"):
        needs.validate([{"kind": "auth_header", "why": "a", "how": "b"}])


def test_validate_defaults_to_required():
    assert needs.validate([{"kind": "tool", "name": "ffuf", "why": "a", "how": "b"}])[0]["required"] is True


# ── 준비됐는지 판정 ────────────────────────────────────────────

class _Mod:
    def __init__(self, items):
        self.needs = needs.validate(items)


AUTH = [{"kind": "auth_header", "name": "Authorization", "why": "a", "how": "b"}]


def test_auth_header_need_follows_the_target(app):
    with app.app_context():
        assert needs.check(_Mod(AUTH), [])[0]["ready"] is False
        assert needs.check(_Mod(AUTH), ["Authorization"])[0]["ready"] is True
        assert needs.check(_Mod(AUTH), ["authorization"])[0]["ready"] is True   # 대소문자 안 가림


def test_env_need_reads_the_environment(app, monkeypatch):
    mod = _Mod([{"kind": "env", "name": "DASH_WORDLISTS", "why": "a", "how": "b"}])
    monkeypatch.delenv("DASH_WORDLISTS", raising=False)
    with app.app_context():
        assert needs.check(mod, [])[0]["ready"] is False
    monkeypatch.setenv("DASH_WORDLISTS", r"C:\lists")
    with app.app_context():
        assert needs.check(mod, [])[0]["ready"] is True


def test_people_only_needs_are_not_judged(app):
    mod = _Mod([{"kind": "tool", "name": "fsmap", "why": "a", "how": "b"}])
    with app.app_context():
        # 사람이 칼리에서 돌렸는지 대시보드는 알 수 없다 — 모른다고 해야지 '없음'이라 하면 안 된다
        assert needs.check(mod, [])[0]["ready"] is None
        assert needs.blocking(mod, []) == []


# ── 화면과 실행 ────────────────────────────────────────────────

def test_module_card_shows_what_to_prepare(app, client):
    add_target(client)
    html = client.get(f"/modules?target={only_target(app)}").get_data(as_text=True)
    assert "실행 전에 준비할 것" in html
    assert "ffuf" in html and "서버 접속" in html


def test_tool_page_shows_the_missing_token(app, client):
    add_target(client)
    tid = only_target(app)
    html = client.get(f"/tools?target={tid}&tool=sesacedu_material_traversal").get_data(as_text=True)
    assert "인증 헤더" in html and "없음 — 지금은 실행해도 실패합니다" in html


def test_run_is_blocked_until_the_token_is_there(app, client):
    add_target(client)
    tid = only_target(app)
    form = {"target_id": tid, "module_id": "sesacedu_material_traversal", "confirm": "yes",
            "paths": "etc/passwd", "scheme": "double-full", "depth": "9", "lecture": "123"}

    page = client.post("/tools/run", data=form, follow_redirects=True).get_data(as_text=True)
    assert "인증 헤더 Authorization 가 있어야 돌아갑니다" in page

    client.post(f"/targets/{tid}/headers", data={"headers": "Authorization: Bearer test-token"},
                follow_redirects=True)
    page = client.get(f"/tools?target={tid}&tool=sesacedu_material_traversal").get_data(as_text=True)
    assert "준비됨" in page


def test_optional_need_does_not_block(app, client, monkeypatch):
    """SecLists 가 없어도 숨은 경로 찾기는 돌아야 한다."""
    monkeypatch.delenv("DASH_WORDLISTS", raising=False)
    add_target(client)
    tid = only_target(app)
    html = client.get(f"/modules?target={tid}").get_data(as_text=True)
    assert "없어도 돌아갑니다" in html
