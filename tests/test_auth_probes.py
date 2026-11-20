"""인증·권한 점검(11-20): 인증·인가, 남의 자원 접근(IDOR), 요청 수 제한.

노션 '웹 서비스 취약점 목록' 의 AUTH 15건·Insecure Design 3건을 보고 만든 모듈들이다.
가짜 서버를 세워 '인증 있이·없이 견주기', '번호 바꿔 보기', '잇달아 보내 막히는지' 를 본다.
"""
from dashboard import core
from dashboard.core import Point, Response
from modules import authz_probe, idor_probe, rate_limit_probe

T = core.Target(id=1, name="t", url="https://sesacedu.store")
AUTH = {"Authorization": "Bearer mine"}
OTHER = {"Authorization": "Bearer theirs"}


def _ctx(monkeypatch, auth=AUTH):
    """대상에 인증 헤더가 설정된 실행인 척한다 — core.fetch 가 그걸 붙이는 자리를 흉내 낸다."""
    monkeypatch.setattr(core, "auth_headers", lambda: dict(auth or {}))


def _server(monkeypatch, handler):
    """handler(url, headers) -> (status, body). headers 는 요청에 실제로 실린 것."""
    sent = []

    def fetch(url, *, method="GET", headers=None, data=None, auth=True, **_kw):
        hdrs = {}
        if auth:
            hdrs.update(core.auth_headers())
        hdrs.update(headers or {})
        sent.append((method, url, hdrs))
        status, body = handler(url, hdrs)
        return Response(url=url, status=status, body=body)
    monkeypatch.setattr(core, "fetch", fetch)
    return sent


def _end(url="https://sesacedu.store/instructor"):
    return Point(method="GET", url=url, param="", place="path")


# ── 인증·인가 점검 ───────────────────────────────────────────

def test_authz_says_what_to_do_when_the_target_has_no_auth(monkeypatch):
    """뗄 인증이 없으면 견줄 수가 없다 — 취약이라 하지 않고 어디에 넣으라고 적는다."""
    _ctx(monkeypatch, auth={})
    _server(monkeypatch, lambda url, h: (200, "page"))
    c = authz_probe.run(T, [_end()], {})[0]
    assert c.verdict == "safe" and "대상 탭" in c.evidence and "인증" in c.evidence


def test_authz_same_answer_without_the_token_is_vuln(monkeypatch):
    """인증 있이와 없이가 같은 응답이면 그 주소에는 인증이 없는 것이다(미수강 자료·강사센터 모양)."""
    _ctx(monkeypatch)
    # 첫 화면과 다른 본문이어야 '화면 틀' 이 아니라 진짜 보호 화면으로 본다
    _server(monkeypatch, lambda url, h: (200, "첫 화면") if url.endswith("/") else (200, "강사센터" * 50))
    c = authz_probe.run(T, [_end()], {})[0]
    assert c.verdict == "vuln" and "인증 없이 열리는 주소" in c.title


def test_authz_different_answer_without_the_token_is_potential(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, h: (200, "내 정보 " * 60) if h.get("Authorization") else (200, "로그인하세요"))
    c = authz_probe.run(T, [_end()], {})[0]
    assert c.verdict == "potential" and "내용 확인 필요" in c.title


def test_authz_finds_a_path_shape_that_walks_past_the_block(monkeypatch):
    """Nginx location 은 경로를 글자로 맞춘다 — //login 은 /login 과 다른 글자다."""
    _ctx(monkeypatch)

    def handler(url, h):
        if h.get("Authorization"):
            return 200, "로그인 화면" * 40
        return (200, "로그인 화면" * 40) if url.endswith("//login") else (403, "forbidden")
    _server(monkeypatch, handler)
    c = authz_probe.run(T, [_end("https://sesacedu.store/login")], {})[0]
    assert c.verdict == "vuln" and "경로 변형" in c.title and "// 겹치기" in c.evidence


def test_authz_blocked_everywhere_is_safe(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, h: (200, "ok" * 40) if h.get("Authorization") else (401, ""))
    c = authz_probe.run(T, [_end()], {})[0]
    assert c.verdict == "safe" and "지나가지 못함" in c.evidence


# ── 남의 자원 접근(IDOR) ─────────────────────────────────────

def _num(sample="103", param="orderId"):
    return Point(method="GET", url="https://sesacedu.store/backend/mypage/buy/history/{orderId}",
                 param=param, place="path", sample=sample)


def test_idor_skips_points_that_are_not_numbers():
    assert idor_probe.targets_of("keyword") == []
    assert idor_probe.targets_of("") == []
    assert [v for v, _ in idor_probe.targets_of("103")][:2] == ["104", "102"]


def test_idor_uuid_gets_one_shot():
    got = idor_probe.targets_of("8f14e45f-ea0b-4f1e-9a2c-1b2c3d4e5f60")
    assert len(got) == 1 and got[0][0].endswith("1")


def test_idor_another_number_opening_is_only_potential(monkeypatch):
    """토큰 하나로는 열린 자원이 내 것인지 남의 것인지 알 수 없다 — 잠재로 둔다."""
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, h: (200, "주문 " + url[-3:] + " 상세" * 20) if h.get("Authorization") else (401, ""))
    c = idor_probe.run(T, [_num()], {})[0]
    assert c.verdict == "potential" and "다른 계정 토큰이 없어 확정하지 못함" in c.evidence


def test_idor_second_account_seeing_the_same_resource_is_vuln(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, h: (200, "주문 103 상세" * 20) if h.get("Authorization") else (401, ""))
    c = idor_probe.run(T, [_num()], {"other_auth": "Authorization: Bearer theirs"})[0]
    assert c.verdict == "vuln" and "다른 계정 토큰으로 같은 자원이 열림" in c.title


def test_idor_without_any_token_is_vuln(monkeypatch):
    _ctx(monkeypatch)
    # 첫 화면과 다른 본문이어야 '화면 틀' 이 아니라 진짜 자원으로 본다
    _server(monkeypatch, lambda url, h: (200, "첫 화면") if url.endswith("/") else (200, "주문 103 상세" * 20))
    c = idor_probe.run(T, [_num()], {})[0]
    assert c.verdict == "vuln" and "인증 없이" in c.title


def test_idor_owner_check_present_is_safe(monkeypatch):
    _ctx(monkeypatch)

    def handler(url, h):
        mine = h.get("Authorization") == "Bearer mine"
        if not h.get("Authorization"):
            return 401, ""
        return (200, "내 주문 상세" * 20) if (mine and url.endswith("/103")) else (403, "")
    _server(monkeypatch, handler)
    c = idor_probe.run(T, [_num()], {"other_auth": "Authorization: Bearer theirs"})[0]
    assert c.verdict == "safe" and "소유자 확인이 있다" in c.evidence


def test_idor_reads_the_other_account_header_line():
    assert idor_probe.parse_line("Authorization: Bearer x\n\n쓰레기줄") == {"Authorization": "Bearer x"}


# ── 요청 수 제한 ─────────────────────────────────────────────

def test_rate_limit_no_block_at_all_is_vuln(monkeypatch):
    sent = _server(monkeypatch, lambda url, h: (200, "로그인 실패"))
    c = rate_limit_probe.run(T, [_end("https://sesacedu.store/login")], {"tries": "6"})[0]
    assert c.verdict == "vuln" and "6회 연속 통과" in c.title and len(sent) == 6


def test_rate_limit_429_is_safe(monkeypatch):
    n = {"i": 0}

    def handler(url, h):
        n["i"] += 1
        return (429, "Too Many Requests") if n["i"] >= 4 else (200, "로그인 실패")
    _server(monkeypatch, handler)
    c = rate_limit_probe.run(T, [_end("https://sesacedu.store/login")], {"tries": "10"})[0]
    assert c.verdict == "safe" and "4 번째에 막힘" in c.evidence


def test_rate_limit_block_that_an_ip_header_undoes_is_vuln(monkeypatch):
    n = {"i": 0}

    def handler(url, h):
        if h.get("X-Forwarded-For"):
            return 200, "로그인 실패"
        n["i"] += 1
        return (429, "Too Many Requests") if n["i"] >= 3 else (200, "로그인 실패")
    _server(monkeypatch, handler)
    c = rate_limit_probe.run(T, [_end("https://sesacedu.store/login")], {"tries": "10"})[0]
    assert c.verdict == "vuln" and "X-Forwarded-For 로 우회" in c.title


def test_rate_limit_post_runs_without_a_confirm_box(monkeypatch):
    """확인 칸은 뺐다(11-20 사용자 지시) — 계정이 잠길 수 있다는 경고는 설명에 남는다."""
    assert "잠길 수 있습니다" in rate_limit_probe.META["description"]
    sent = _server(monkeypatch, lambda url, h: (200, "ok"))
    c = rate_limit_probe.run(T, [_end()], {"method": "POST", "tries": "3"})[0]
    assert c.verdict == "vuln" and len(sent) == 3
    assert all(m == "POST" for m, _u, _h in sent)


def test_rate_limit_post_body_is_read_line_by_line():
    assert rate_limit_probe._body("email=a@b.c\npassword=wrong") == {"email": "a@b.c", "password": "wrong"}
    assert rate_limit_probe._body("") is None


def test_rate_limit_counts_a_retry_after_header_as_a_block(monkeypatch):
    def fetch(url, *, method="GET", headers=None, data=None, auth=True, **_kw):
        return Response(url=url, status=200, body="ok", headers=[("Retry-After", "30")])
    monkeypatch.setattr(core, "fetch", fetch)
    c = rate_limit_probe.run(T, [_end()], {"tries": "5"})[0]
    assert c.verdict == "safe" and "Retry-After" in c.evidence


# ── 모듈 등록 ────────────────────────────────────────────────

def test_the_new_probes_are_registered_with_the_notion_vocabulary(app):
    from dashboard import routes
    with app.test_request_context():
        mods = routes._modules()
    assert mods["authz_probe"].vuln == "AUTH" and mods["authz_probe"].unit == "endpoint"
    assert mods["idor_probe"].vuln == "AUTH" and mods["idor_probe"].unit == "param"
    assert mods["rate_limit_probe"].vuln == "Insecure Design"
    assert all(mods[m].stage == "probe" for m in ("authz_probe", "idor_probe", "rate_limit_probe"))


def test_authz_does_not_call_a_spa_shell_an_open_page(monkeypatch):
    """React·Vue 앱은 어느 주소를 불러도 같은 index.html 을 준다 — 그걸 '인증 없이 열림' 이라 하면 안 된다.

    11-21 실측: 사용자 웹의 /mypage·/instructor·/mypage/buy·/mypage/cart 가 전부 564바이트짜리
    같은 껍데기였는데 모듈이 취약 6 으로 적었다.
    """
    _ctx(monkeypatch)
    SHELL = "<!doctype html><html><div id=root></div></html>"
    _server(monkeypatch, lambda url, h: (200, SHELL))
    c = authz_probe.run(T, [_end("https://sesacedu.store/mypage")], {})[0]
    assert c.verdict == "safe"
    assert "화면 틀(SPA 껍데기)" in c.evidence and "HAR" in c.evidence


def test_authz_still_flags_a_real_page_that_differs_from_the_shell(monkeypatch):
    _ctx(monkeypatch)
    SHELL = "<!doctype html><html><div id=root></div></html>"
    _server(monkeypatch, lambda url, h: (200, SHELL) if url.endswith("/") else (200, "강사센터 목록" * 40))
    c = authz_probe.run(T, [_end("https://sesacedu.store/backend/instructor")], {})[0]
    assert c.verdict == "vuln" and "인증 없이 열리는 주소" in c.title


def _path(param="orderId", sample=""):
    return Point(method="GET", url="https://sesacedu.store/backend/mypage/buy/history/{orderId}",
                 param=param, place="path", sample=sample)


def test_idor_finds_a_baseline_number_when_the_point_has_no_sample(monkeypatch):
    """API 명세에서 온 지점은 표본 값이 없다 — 11-21 실측에서 10개가 통째로 건너뛰어졌다.

    번호 자리면 몇 개 넣어 보고 내용이 오는 것을 기준으로 삼는다.
    """
    _ctx(monkeypatch)

    def handler(url, h):
        n = url.rstrip("/").rsplit("/", 1)[-1]
        if n == "3":
            return 200, "주문 3 상세" * 20          # 1·2 는 비고 3 만 내용이 있다
        return 404, ""
    _server(monkeypatch, handler)
    c = idor_probe.run(T, [_path()], {})[0]
    assert "기준 번호 찾기(1)" in c.evidence and "3 이 내용을 돌려줌" in c.evidence


def test_idor_skips_a_path_point_that_answers_to_nothing(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, h: (404, ""))
    assert idor_probe.run(T, [_path()], {}) == []


def test_idor_leaves_query_points_without_a_sample_alone(monkeypatch):
    """쿼리 파라미터는 이름만 보고 번호를 넣어 볼 수 없다 — keyword=1 은 뜻이 없다."""
    _ctx(monkeypatch)
    sent = _server(monkeypatch, lambda url, h: (200, "x" * 100))
    assert idor_probe.run(T, [Point(method="GET", url="https://sesacedu.store/backend/lectures",
                                    param="keyword", place="query", sample="")], {}) == []
    # 첫 화면 한 번(화면 틀 잣대)만 나가고 지점에는 아무것도 안 보낸다
    assert [u for _m, u, _h in sent] == ["https://sesacedu.store/"]


def test_idor_does_not_call_a_spa_shell_an_open_resource(monkeypatch):
    """11-21 실측: /mypage/buy/history/1 등 7개가 전부 564바이트 껍데기인데 취약으로 적혔다."""
    _ctx(monkeypatch)
    SHELL = "<!doctype html><html><div id=root></div></html>"
    _server(monkeypatch, lambda url, h: (200, SHELL))
    out = idor_probe.run(T, [_path()], {})
    assert out == [] or out[0].verdict == "safe"
    ev = "" if not out else out[0].evidence
    assert out == [] or ("화면 틀(SPA 껍데기)" in ev and "HAR" in ev)
