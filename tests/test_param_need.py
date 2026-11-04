"""입력칸이 필수인지 선택인지 — 안 보이면 못 쓴다는 지적(11-05).

사람이 칸을 보고 **비워 둬도 되는지** 바로 알아야 한다. 모듈마다 적어 두게 하고,
새 모듈이 빠뜨리면 여기서 걸린다.
"""
import re

import pytest

NEEDS = ("required", "optional", "conditional")


def all_params(app):
    with app.app_context():
        for m in app.config["MODULES"].values():
            for p in m.params or []:
                yield m.id, p


def test_every_input_says_whether_it_can_be_left_empty(app):
    missing = [f"{mid}.{p['name']}" for mid, p in all_params(app) if p.get("need") not in NEEDS]
    assert not missing, "need 를 안 적은 칸: " + ", ".join(missing)


def test_a_conditional_input_says_when_it_is_used(app):
    """'고를 때만' 이라고만 하면 언제인지 모른다."""
    bad = [f"{mid}.{p['name']}" for mid, p in all_params(app)
           if p.get("need") == "conditional" and not p.get("when")]
    assert not bad, "언제 쓰는지 안 적은 칸: " + ", ".join(bad)


def test_labels_do_not_say_http_status_codes(app):
    """화면에서 읽는 사람은 응답 코드를 모른다 — '500 의 종류를 가릴지' 같은 말(11-05)."""
    bad = [f"{mid}.{p['name']}: {p.get('label')}" for mid, p in all_params(app)
           if re.search(r"\b[1-5]\d\d\b", p.get("label") or "")]
    assert not bad, "칸 이름에 응답 코드가 들어 있습니다: " + " · ".join(bad)


@pytest.mark.parametrize("need, word", [("required", "필수"), ("optional", "선택"),
                                        ("conditional", "고를 때만")])
def test_the_mark_shows_up_on_the_module_page(app, client, need, word):
    """퍼징 모듈 한 곳에 세 가지가 다 있다 — mode(필수)·hints(선택)·base(고를 때만)."""
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹",
                                  "url": "https://sesacedu.store"}, follow_redirects=True)
    page = client.get("/tools?tool=sesacedu_material_traversal_fuzz").get_data(as_text=True)
    assert f'class="req-mark {"req" if need == "required" else "when" if need == "conditional" else "opt"}"' in page
    assert word in page


def test_a_module_that_forgot_falls_back_to_the_default_rule(app):
    """모듈이 안 적어 뒀으면 화면이 기본값 유무로 정한다 — 빈 화면이 되지는 않는다."""
    from flask import render_template_string
    tpl = ('{% from "_macros.html" import param_input %}'
           '{{ param_input({"name": "x", "label": "무언가", "default": ""}) }}')
    with app.test_request_context():
        assert "필수" in render_template_string(tpl)


# ── 설명 글의 **강조** ─────────────────────────────────────────────

def test_double_stars_turn_into_bold(app):
    """모듈 글에 쓰는 표시인데 그동안 별 두 개가 그대로 보였다(11-05)."""
    from dashboard import strong
    assert str(strong("앞 **가운데** 뒤")) == "앞 <b>가운데</b> 뒤"


def test_the_rest_of_the_text_is_still_escaped(app):
    """먼저 이스케이프하고 표시만 감싼다 — 모듈 글의 꺾쇠가 태그가 되면 안 된다."""
    from dashboard import strong
    out = str(strong("<script>x</script> **굵게**"))
    assert "<script>" not in out and "&lt;script&gt;" in out and "<b>굵게</b>" in out


def test_the_form_has_no_leftover_stars(app, client):
    client.post("/targets", data={"project": "sesacedu", "role": "user_web", "name": "웹",
                                  "url": "https://sesacedu.store"}, follow_redirects=True)
    page = client.get("/tools?tool=sesacedu_material_traversal_fuzz").get_data(as_text=True)
    body = page.split('class="tool-form"', 1)[-1]
    assert "**" not in body
