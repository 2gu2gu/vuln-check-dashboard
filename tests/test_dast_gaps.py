"""DAST 로 볼 수 있는 남은 항목(11-20): JWT 토큰, 파일 업로드 검증, Log4j 치환.

노션 '웹 서비스 취약점 목록' 에서 '수동으로만 되는 것'(비밀번호 MD5 저장, 수료 조건 미집행)을 빼고
**요청·응답으로 드러나는 것** 만 모듈로 만든 것이다. 가짜 서버로 각 단계가 무엇을 보고 판정하는지 본다.
"""
import base64
import json
import time

from dashboard import core
from dashboard.core import Point, Response
from modules import jndi_probe, jwt_probe, upload_probe

T = core.Target(id=1, name="t", url="https://sesacedu.store")


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def token(head=None, body=None, sig="sIgNaTuRe"):
    return f"{_b64({'alg': 'HS256', 'typ': 'JWT', **(head or {})})}.{_b64({'sub': '7', 'auth': 1, **(body or {})})}.{sig}"


def _ctx(monkeypatch, auth=None):
    monkeypatch.setattr(core, "auth_headers", lambda: dict(auth if auth is not None else {}))


def _server(monkeypatch, handler):
    """handler(url, method, headers, body) -> (status, body) 또는 (status, body, 걸릴 초)."""
    sent = []

    def fetch(url, *, method="GET", headers=None, data=None, raw_body=None, content_type="", auth=True, **_kw):
        hdrs = dict(core.auth_headers()) if auth else {}
        hdrs.update(headers or {})
        sent.append({"method": method, "url": url, "headers": hdrs, "body": raw_body or b"", "ctype": content_type})
        got = handler(url, method, hdrs, raw_body or b"")   # 핸들러가 OSError 를 던지면 그대로 올라간다
        status, body = got[0], got[1]
        if len(got) > 2 and got[2]:
            time.sleep(got[2])
        return Response(url=url, status=status, body=body)
    monkeypatch.setattr(core, "fetch", fetch)
    return sent


def _end(url="https://sesacedu.store/backend/lectures/103/assignments/file"):
    return Point(method="POST", url=url, param="", place="path")


# ── JWT 토큰 점검 ────────────────────────────────────────────

def test_jwt_splits_a_token_and_refuses_junk():
    assert jwt_probe.split(token())[0]["alg"] == "HS256"
    assert jwt_probe.split("not.a.jwt") is None
    assert jwt_probe.split("onlyonepart") is None


def test_jwt_is_found_in_the_target_auth_header(monkeypatch):
    t = token()
    _ctx(monkeypatch, {"Authorization": f"Bearer {t}"})
    assert jwt_probe.find_token({}) == t
    _ctx(monkeypatch, {"Cookie": f"sid=abc; access={t}"})
    assert jwt_probe.find_token({}) == t


def test_jwt_says_so_when_there_is_no_token(monkeypatch):
    _ctx(monkeypatch)
    f = jwt_probe.run(T, {})[0]
    assert "찾지 못했습니다" in f.title and "2. 인증" in f.evidence


def test_jwt_alg_none_and_missing_exp_are_found_without_sending_anything(monkeypatch):
    _ctx(monkeypatch, {"Authorization": "Bearer " + token({"alg": "none"})})
    _server(monkeypatch, lambda *a: (500, "이 점검은 요청을 보내면 안 된다"))
    titles = [f.title for f in jwt_probe.run(T, {})]
    assert any("alg=none" in t for t in titles) and any("만료(exp)가 없습니다" in t for t in titles)


def test_jwt_a_long_expiry_is_low(monkeypatch):
    _ctx(monkeypatch, {"Authorization": "Bearer " + token(body={"exp": int(time.time()) + 86400 * 30})})
    out = jwt_probe.run(T, {})
    assert any("만료가 너무 깁니다" in f.title and f.severity == "low" for f in out)


def test_jwt_sensitive_claims_are_reported(monkeypatch):
    _ctx(monkeypatch, {"Authorization": "Bearer " + token(body={"exp": int(time.time()) + 60, "email": "a@b.c"})})
    out = jwt_probe.run(T, {})
    assert any("민감한 클레임" in f.title for f in out)


def test_jwt_tampered_token_that_still_works_is_reported(monkeypatch):
    """서명만 바꾼 토큰이 통하면 서명 검증이 없는 것이다."""
    _ctx(monkeypatch, {"Authorization": "Bearer " + token(body={"exp": int(time.time()) + 60})})
    _server(monkeypatch, lambda url, m, h, b: (200, "내 정보"))
    out = jwt_probe.run(T, {"verify_url": "https://sesacedu.store/backend/mypage"})
    assert any("서명 검증 없음" in f.title and f.severity in ("high", "critical") for f in out)


def test_jwt_signature_checked_is_only_info(monkeypatch):
    t = token(body={"exp": int(time.time()) + 60})
    _ctx(monkeypatch, {"Authorization": "Bearer " + t})
    _server(monkeypatch, lambda url, m, h, b: (200, "내 정보") if t in h.get("Authorization", "") else (401, ""))
    out = jwt_probe.run(T, {"verify_url": "https://sesacedu.store/backend/mypage"})
    assert any("서명 검증은 있습니다" in f.title and f.severity == "info" for f in out)


def test_jwt_raised_claim_is_critical(monkeypatch):
    t = token(body={"exp": int(time.time()) + 60, "auth": 1})
    _ctx(monkeypatch, {"Authorization": "Bearer " + t})
    _server(monkeypatch, lambda url, m, h, b: (200, "ok"))
    out = jwt_probe.run(T, {"verify_url": "https://sesacedu.store/backend/mypage"})
    # 서명만 바꾼 것이 먼저 걸리므로 '권한' 까지 가지 않는다 — 올리는 토큰이 만들어지는지는 variants 로 본다
    kinds = [k for k, _, _ in jwt_probe.variants({"alg": "HS256"}, {"auth": 1}, "sig")]
    assert "권한 클레임을 올린 토큰" in kinds
    assert any("서명 검증 없음" in f.title for f in out)


def test_jwt_still_working_after_logout_is_reported(monkeypatch):
    """노션 'JWT 토큰 폐기 메커니즘 부재' 와 같은 모양 — 로그아웃 뒤에도 같은 토큰이 통한다."""
    t = token(body={"exp": int(time.time()) + 60})
    _ctx(monkeypatch, {"Authorization": "Bearer " + t})
    # 서명 검증은 있고(손댄 토큰은 401), 폐기는 없다(로그아웃 뒤에도 원래 토큰은 200)
    _server(monkeypatch, lambda url, m, h, b: (200, "내 정보") if t in h.get("Authorization", "") else (401, ""))
    out = jwt_probe.run(T, {"verify_url": "https://sesacedu.store/backend/mypage",
                            "logout_url": "https://sesacedu.store/backend/auth/logout"})
    assert any("폐기 장치 없음" in f.title for f in out)


def test_jwt_without_a_verify_url_only_reads_the_token(monkeypatch):
    _ctx(monkeypatch, {"Authorization": "Bearer " + token(body={"exp": int(time.time()) + 60})})
    sent = _server(monkeypatch, lambda *a: (200, "ok"))
    out = jwt_probe.run(T, {})
    assert any("뜯어 보기까지만" in f.title for f in out) and sent == []


# ── 파일 업로드 검증 점검 ────────────────────────────────────

def test_jwt_an_already_expired_token_is_said_out_loud(monkeypatch):
    """11-20 실측: 대상 토큰이 5시간 전에 끝나 있어 인증이 필요한 점검이 전부 ① 에서 멈췄는데 아무 말이 없었다."""
    _ctx(monkeypatch, {"Authorization": "Bearer " + token(body={"exp": int(time.time()) - 3600})})
    out = jwt_probe.run(T, {})
    hit = [f for f in out if "이미 만료됐습니다" in f.title]
    assert hit and "분 전에 끝났습니다" in hit[0].evidence     # 분은 제목이 아니라 근거에
    assert "(" not in hit[0].title                            # 돌릴 때마다 새 줄이 쌓이면 안 된다
    assert "2. 인증" in hit[0].evidence and "IDOR" in hit[0].evidence


def test_upload_warns_that_files_stay_even_without_a_confirm_box(monkeypatch):
    """확인 칸은 뺐다(11-20 사용자 지시) — 없앤 것은 문턱이고, 남는다는 경고는 그대로다."""
    assert "남습니다" in upload_probe.META["description"]
    assert "직접 지우세요" in upload_probe.META["description"]
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, m, h, b: (400, ""))
    c = upload_probe.run(T, [_end()], {})[0]          # 글자를 적지 않아도 돈다
    assert c.verdict == "safe"


def test_upload_builds_multipart_that_keeps_the_raw_filename():
    """이름에 `..` 와 역슬래시를 그대로 실어야 경로 조작 점검이 성립한다."""
    body, head = upload_probe.multipart("file", "..\\x.jsp", "application/octet-stream", b"x", [("title", "t")])
    assert b'filename="..\\x.jsp"' in body and b'name="title"' in body
    assert head.startswith("multipart/form-data; boundary=") and head.split("=")[1].encode() in body


def test_upload_runnable_extension_accepted_is_vuln(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, m, h, b: (200, "올렸습니다"))
    c = upload_probe.run(T, [_end()], {})[0]
    assert c.verdict == "vuln" and c.title == "업로드 확장자 검증 없음" and c.severity == "critical"
    assert ".jsp" in c.evidence                   # 어떤 확장자였는지는 근거에


def test_upload_path_in_the_name_accepted_is_vuln(monkeypatch):
    """확장자는 가리지만 이름의 경로는 안 가리는 서버 — 노션 '과제 업로드 경로 조작' 모양."""
    _ctx(monkeypatch)

    def h(url, m, hd, body):
        name = body.split(b'filename="')[1].split(b'"')[0].decode("utf-8", "replace")
        if name.lower().endswith((".jsp", ".jspx", ".php", ".html")) and ".." not in name and "\\" not in name \
                and not name.startswith("/"):
            return 400, "확장자 불가"
        return 200, "올렸습니다"
    _server(monkeypatch, h)
    c = upload_probe.run(T, [_end()], {})[0]
    assert c.verdict == "vuln" and "경로 조작" in c.title and "③ 심화" in c.evidence


def test_upload_everything_blocked_is_safe(monkeypatch):
    _ctx(monkeypatch)

    def h(url, m, hd, body):
        name = body.split(b'filename="')[1].split(b'"')[0].decode("utf-8", "replace")
        bad = (".." in name or "\\" in name or "%00" in name or ";" in name or name.startswith("/")
               or any(e in name.lower() for e in (".jsp", ".php", ".html")))
        ok = name.endswith(".txt") and not bad   # 이름을 제대로 가리는 서버. 겹친 확장자도 막는다
        del hd  # Content-Type 은 보지 않는다 — 이름으로 가린다
        return (200, "올렸습니다") if ok else (400, "안 됩니다")
    _server(monkeypatch, h)
    c = upload_probe.run(T, [_end()], {})[0]
    assert c.verdict == "safe" and "모두 막힘" in c.evidence


def test_upload_says_what_to_fix_when_even_a_txt_fails(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, m, h, b: (400, "lectureId 가 없습니다"))
    c = upload_probe.run(T, [_end()], {})[0]
    assert c.verdict == "safe" and "HAR" in c.evidence and "칸 이름" in c.evidence


def test_upload_sends_the_extra_fields(monkeypatch):
    _ctx(monkeypatch)
    sent = _server(monkeypatch, lambda url, m, h, b: (400, ""))
    upload_probe.run(T, [_end()], {"extra": "lectureId=103\ntitle=점검"})
    assert b'name="lectureId"' in sent[0]["body"] and b"103" in sent[0]["body"]


# ── Log4j 치환 점검 ─────────────────────────────────────────

def test_jndi_warns_about_the_outbound_connection_without_a_confirm_box():
    """확인 칸은 뺐다(11-20 사용자 지시). 바깥으로 연결하게 만든다는 말은 설명에 남는다."""
    d = jndi_probe.META["description"]
    assert "바깥으로 연결" in d and "문서용 대역" in d


def test_jndi_substitution_coming_back_is_vuln(monkeypatch):
    """보낸 글자가 아니라 치환 결과가 돌아오면 Log4j 가 값을 해석한 것이다."""
    _ctx(monkeypatch)

    def h(url, m, hd, body):
        ua = hd.get("User-Agent", "")
        if ua.startswith("${::-") and ua.endswith("}"):
            return 500, "오류: " + ua[5:-1]          # 치환해서 적는 서버
        return 500, "오류: " + ua                     # 값을 그대로 되돌려 준다
    _server(monkeypatch, h)
    c = jndi_probe.run(T, [_end("https://sesacedu.store/courses/detail")], {})[0]
    assert c.verdict == "vuln" and "치환이 살아 있음" in c.title and c.severity == "critical"


def test_jndi_slow_answer_to_a_blackhole_lookup_is_potential(monkeypatch):
    _ctx(monkeypatch)

    def h(url, m, hd, body):
        if "jndi" in hd.get("User-Agent", ""):
            return 200, "ok", 1.2                    # 연결을 기다리는 척
        return 200, "ok"
    _server(monkeypatch, h)
    c = jndi_probe.run(T, [_end("https://sesacedu.store/courses/detail")], {})[0]
    assert c.verdict == "potential" and "응답 지연" in c.title


def test_jndi_nothing_observable_is_safe_and_says_so(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, m, h, b: (200, "정적인 화면"))
    c = jndi_probe.run(T, [_end("https://sesacedu.store/courses/detail")], {})[0]
    assert c.verdict == "safe" and "리스너로 한 번 더 보는 게 확실하다" in c.evidence


def test_jndi_a_dead_answer_to_the_lookup_is_vuln(monkeypatch):
    """11-20 실측에서 실제로 일어난 일 — jndi 를 걸자 응답이 끊겼다.

    그때는 예외가 실행 전체를 끊어 아무 기록도 남지 않았다. 지금은 가장 센 신호로 적는다.
    표식만 보낼 때는 멀쩡했고 두 번 다 끊겼을 때만 취약이다.
    """
    _ctx(monkeypatch)

    def h(url, m, hd, body):
        if "jndi" in hd.get("User-Agent", ""):
            raise OSError("The read operation timed out")
        return 200, "ok"
    _server(monkeypatch, h)
    c = jndi_probe.run(T, [_end("https://sesacedu.store/courses/detail")], {})[0]
    assert c.verdict == "vuln" and "응답이 끊김" in c.title
    assert "한 번 더 보내도 끊김" in c.evidence


def test_jndi_a_dead_answer_only_once_is_potential(monkeypatch):
    _ctx(monkeypatch)
    n = {"i": 0}

    def h(url, m, hd, body):
        if "jndi" in hd.get("User-Agent", ""):
            n["i"] += 1
            if n["i"] == 1:
                raise OSError("timed out")
        return 200, "ok"
    _server(monkeypatch, h)
    c = jndi_probe.run(T, [_end("https://sesacedu.store/courses/detail")], {})[0]
    assert c.verdict == "potential" and "확정 안 됨" in c.title


def test_jndi_a_slow_address_is_not_called_vulnerable(monkeypatch):
    """표식만 보낸 것도 끊기는 주소는 그냥 느린 것이다 — 그걸로 취약이라 하면 안 된다."""
    _ctx(monkeypatch)

    def h(url, m, hd, body):
        raise OSError("timed out")
    _server(monkeypatch, h)
    c = jndi_probe.run(T, [_end("https://sesacedu.store/slow")], {})[0]
    assert c.verdict == "safe" and "기준 응답을 받지 못함" in c.evidence


def test_jndi_blackhole_target_is_a_documentation_range():
    """남의 서비스로 연결을 걸게 만들지 않는다 — RFC 5737 문서용 대역만 쓴다."""
    assert jndi_probe.BLACKHOLE.startswith("198.51.100.")
    assert all(jndi_probe.BLACKHOLE in v for v, _ in jndi_probe.jndi(jndi_probe.BLACKHOLE, "m"))


def test_jndi_listener_result_is_left_to_the_listener(monkeypatch):
    _ctx(monkeypatch)
    _server(monkeypatch, lambda url, m, h, b: (200, "정적인 화면"))
    c = jndi_probe.run(T, [_end("https://sesacedu.store/courses/detail")],
                       {"listener": "13.125.54.149:389"})[0]
    assert "걸려 온 조회가 있는지 직접 보세요" in c.evidence and "이 모듈은 못 봅니다" in c.evidence
    assert c.verdict == "safe" and "리스너 확인 필요" in c.title


def test_jndi_obfuscated_shapes_are_tried():
    shapes = [k for _, k in jndi_probe.jndi("h:1", "m")]
    assert "글자를 조회식으로 가림" in shapes and "글자마다 기본값 치환" in shapes


# ── 모듈 등록 ────────────────────────────────────────────────

def test_the_new_modules_are_registered_with_the_notion_vocabulary(app):
    from dashboard import routes
    with app.test_request_context():
        mods = routes._modules()
    assert mods["jwt_probe"].vuln == "AUTH" and mods["jwt_probe"].stage == "check"
    assert mods["upload_probe"].vuln == "FILE" and mods["upload_probe"].unit == "endpoint"
    assert mods["jndi_probe"].vuln == "RCE" and mods["jndi_probe"].unit == "endpoint"


def test_jndi_tries_every_header_not_just_the_first(monkeypatch):
    """11-20 실측: 사용자 웹 /login 은 User-Agent 가 아니라 다른 헤더로도 터질 수 있다.

    로그에 적히는 자리가 주소마다 다르다. 첫 헤더만 보고 '안전' 이라 하면 나머지를 놓친다.
    """
    _ctx(monkeypatch)

    def h(url, m, hd, body):
        if "jndi" in hd.get("X-Api-Version", ""):   # 네 번째 헤더에서만 터진다
            raise OSError("timed out")
        return 200, "ok"
    _server(monkeypatch, h)
    c = jndi_probe.run(T, [_end("https://sesacedu.store/login")], {})[0]
    assert c.verdict == "vuln" and c.title == "jndi 조회로 응답이 끊김(바깥 연결 시도)"
    assert "X-Api-Version" in c.evidence          # 어느 헤더였는지는 근거에


# ── 표면 품질(11-21 실측에서 드러난 것) ─────────────────────

def test_spec_base_is_recovered_when_servers_lies(monkeypatch):
    """명세의 servers 가 `/backend` 를 빼먹어도 명세를 찾은 자리에서 되찾는다.

    11-21 실측: 새싹에듀 명세는 `https://sesacedu.store` 라고만 적어 두었는데 실제 API 는
    `/backend` 아래에 있다. 그걸 믿어 모은 주소가 전부 화면 라우트(SPA 껍데기)로 떨어졌다.
    """
    from dashboard import discovery as dv
    doc = {"servers": [{"url": "https://sesacedu.store"}], "paths": {"/lectures": {"get": {}}}}
    assert dv.base_candidates(doc, "https://sesacedu.store/backend/v3/api-docs") == ["", "/backend"]

    SHELL = "<!doctype html>앱 껍데기"

    def get(url):
        if url.endswith("/backend/lectures"):
            return Response(url=url, status=200, body='{"lectures":[]}')
        return Response(url=url, status=200, body=SHELL)       # 나머지는 화면 틀
    base, why = dv.pick_base(doc, "https://sesacedu.store/backend/v3/api-docs", "https://sesacedu.store", get)
    assert base == "/backend" and "화면 라우트였다" in why


def test_spec_base_keeps_what_the_spec_says_when_it_works(monkeypatch):
    from dashboard import discovery as dv
    doc = {"servers": [{"url": "https://sesacedu.store/api"}], "paths": {"/lectures": {"get": {}}}}
    get = lambda url: Response(url=url, status=200, body='{"ok":true}' if "/api/" in url else "첫 화면")
    base, _why = dv.pick_base(doc, "https://sesacedu.store/v3/api-docs", "https://sesacedu.store", get)
    assert base == "/api"


def test_url_import_makes_a_point_for_each_path_variable():
    """URL 목록으로 경로 틀을 넣으면 변수도 고를 수 있어야 한다 — 없으면 IDOR 이 고를 게 없다."""
    from modules import surface_import
    pts = surface_import.run(T, {"urls": "https://sesacedu.store/backend/lectures/{lid}/qna/{qnaid}"})
    got = {(p.param, p.place) for p in pts}
    assert ("lid", "path") in got and ("qnaid", "path") in got


def test_path_ids_are_harvested_from_the_listing_above(monkeypatch):
    """`/lectures/{lid}/qna/{qnaid}` 를 1/1 로 부르면 404 다 — 한 단계 위 목록에서 번호를 거둔다."""
    from dashboard import probe
    seen = []

    def fetch(url, **_kw):
        seen.append(url)
        if url.endswith("/backend/lectures"):
            return Response(url=url, status=200, body='{"lectures":[{"lectureId":103}]}')
        if url.endswith("/backend/lectures/103"):
            return Response(url=url, status=200, body='{"ok":1}')
        return Response(url=url, status=404, body="")
    monkeypatch.setattr(core, "fetch", fetch)
    monkeypatch.setattr(core, "run_cache", dict)
    ids = probe.path_ids("https://sesacedu.store/backend/lectures/{lid}/qna/{qnaid}", skip="qnaid")
    assert ids["lid"] == "103" and ids["qnaid"] == ""
    assert probe.fill_path("https://sesacedu.store/backend/lectures/{lid}/qna/{qnaid}", "qnaid", "460") \
        == "https://sesacedu.store/backend/lectures/103/qna/460"


def test_path_ids_fall_back_when_the_listing_says_nothing(monkeypatch):
    from dashboard import probe
    monkeypatch.setattr(core, "run_cache", dict)
    monkeypatch.setattr(core, "fetch", lambda url, **_k: Response(url=url, status=404, body=""))
    ids = probe.path_ids("https://sesacedu.store/backend/lectures/{lid}", skip="")
    assert ids["lid"] == "1"


def test_the_confirm_boxes_are_all_gone():
    """확인 칸(WRITE·UPLOAD·SEND·JNDI)은 전부 뺐다(11-20·21 사용자 지시). 경고는 설명에 남는다."""
    from modules import jndi_probe, rate_limit_probe, stored_xss_probe, upload_probe
    from projects.sesacedu.modules import sesacedu_forum_stored_xss, sesacedu_xss
    for mod in (upload_probe, jndi_probe, rate_limit_probe, stored_xss_probe,
                sesacedu_forum_stored_xss, sesacedu_xss):
        names = {p["name"] for p in mod.META.get("params", [])}
        assert not {n for n in names if n.endswith("_ack")}, mod.META["id"]


def test_tool_cache_skips_what_sqlite_cannot_store(app):
    """고는 빠르게 하자는 것이지 결과가 아니다 — 저장 못 할 항목 하나가 실행을 날리면 안 된다.

    11-21: path_ids 가 튜플 열쇠를 남겨 이미 끝난 IDOR 실행의 결과가 통째로 사라졌다.
    """
    from dashboard import routes
    from dashboard.db import get_db
    from tests.test_app import add_target, target_id
    with app.test_client() as c:
        add_target(c, "https://sesacedu.store", name="t")
    with app.app_context():
        tid = get_db().execute("SELECT id FROM targets").fetchone()["id"]
        routes._save_cache(tid, "mod", {"ok": "값", ("튜플",): "x", "dict": {"a": 1}})
        rows = {r["key"]: r["value"] for r in get_db().execute("SELECT key, value FROM tool_cache")}
    assert rows == {"ok": "값"}


def test_path_ids_cache_survives_a_round_trip_through_sqlite(monkeypatch):
    """찾아 둔 번호는 글자로 저장돼야 다음 모듈이 다시 읽는다."""
    from dashboard import probe
    store = {}
    monkeypatch.setattr(core, "run_cache", lambda: store)
    monkeypatch.setattr(core, "fetch", lambda url, **_k: Response(
        url=url, status=200 if url.endswith("/lectures/1") else 404, body="x" * 50))
    url = "https://sesacedu.store/backend/lectures/{lid}"
    first = probe.path_ids(url, skip="")
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in store.items())
    assert probe.path_ids(url, skip="") == first          # 두 번째는 고에서 읽는다


def test_the_headline_number_says_what_it_counts(app, client):
    """'전체 결과 292' 가 '취약점 292개' 로 읽혔다(11-21 사용자 지적).

    센 단위(한 주소·한 항목이 1건)와 등급을 같이 적어야 숫자를 잘못 읽지 않는다.
    """
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store", name="t")
    html = client.get("/").get_data(as_text=True)
    assert "문제 종류" in html and "가지" in html
    assert "같은 문제도 자리마다 1건으로 셉니다" in html
    assert "전체 결과</small>" not in html


def test_false_positives_are_not_counted_as_vulnerabilities(app, client):
    """오탐으로 표시한 것은 취약 수에서 빠져야 한다 — 표시해 두고 숫자에 넣으면 뜻이 없다."""
    from dashboard import stats
    from dashboard.db import get_db
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store", name="t")
    with app.app_context():
        db = get_db()
        t = db.execute("SELECT * FROM targets").fetchone()
        rid = db.execute("INSERT INTO runs (target_id, module_id, started_at, status) VALUES (?,?,?,?)",
                         [t["id"], "m", "2026-11-21", "done"]).lastrowid
        for i, (sev, st) in enumerate([("high", "open"), ("info", "open"), ("high", "false_positive")]):
            db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, "
                       "recommendation, technique, status, created_at, last_seen) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       [rid, t["id"], "m", f"t{i}", sev, f"/p{i}", "", "", "T1190", st, "2026-11-21", "2026-11-21"])
        db.commit()
        act = stats.activity(db, [t])
    assert act["findings"] == 3 and act["info"] == 1 and act["false"] == 1
    assert act["findings"] - act["info"] - act["false"] == 1       # 진짜 취약점은 하나다
    assert act["kinds"] == 1                                       # 종류로도 하나


def test_false_positives_can_be_purged(app, client):
    """오탐은 표시만 해 두면 표가 계속 길어진다 — 지울 수 있어야 한다(11-21 사용자 지시)."""
    from dashboard.db import get_db
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store", name="t")
    with app.app_context():
        db = get_db()
        tid = db.execute("SELECT id FROM targets").fetchone()["id"]
        rid = db.execute("INSERT INTO runs (target_id, module_id, started_at, status) VALUES (?,?,?,?)",
                         [tid, "m", "2026-11-21", "done"]).lastrowid
        for i, st in enumerate(["open", "false_positive", "false_positive"]):
            db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, "
                       "recommendation, technique, status, created_at, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       [rid, tid, "m", f"t{i}", "high", f"/p{i}", "", "", "T1190", st, "2026-11-21", "2026-11-21"])
        db.commit()
    r = client.post("/findings/purge-false", data={"target_id": tid}, follow_redirects=True)
    assert "오탐으로 표시한 결과 2건을 지웠습니다" in r.get_data(as_text=True)
    with app.app_context():
        rows = get_db().execute("SELECT status FROM findings").fetchall()
    assert [r["status"] for r in rows] == ["open"]          # 오탐이 아닌 것은 그대로


def test_kinds_and_places_are_counted_apart(app, client):
    """같은 문제가 주소 52곳에서 나오면 건수는 52, 종류는 1이다 — 섞으면 숫자를 잘못 읽는다."""
    from dashboard import stats
    from dashboard.db import get_db
    from tests.test_app import add_target
    add_target(client, "https://sesacedu.store", name="t")
    with app.app_context():
        db = get_db()
        t = db.execute("SELECT * FROM targets").fetchone()
        rid = db.execute("INSERT INTO runs (target_id, module_id, started_at, status) VALUES (?,?,?,?)",
                         [t["id"], "header_probe", "2026-11-21", "done"]).lastrowid
        for i in range(5):                       # 같은 제목·같은 모듈, 자리만 다르다
            db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, "
                       "recommendation, technique, status, created_at, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       [rid, t["id"], "header_probe", "보안 설정 미흡", "medium", f"/p{i}", "", "", "T1595.002",
                        "open", "2026-11-21", "2026-11-21"])
        db.commit()
        act = stats.activity(db, [t])
    assert act["findings"] == 5 and act["kinds"] == 1


def test_titles_do_not_carry_details_that_split_one_problem(monkeypatch):
    """제목은 '무슨 문제인가' 만 적는다 — 세부가 섞이면 같은 문제가 여러 종류로 갈린다.

    11-21 실측: 보안 헤더 미흡이 빠진 헤더 목록 때문에 48곳짜리와 4곳짜리 두 종류로 세어졌다.
    더 나쁜 것은 분·시간이 든 제목이다 — 돌릴 때마다 새 줄이 쌓인다(JWT 만료).
    """
    from modules import header_probe
    seen = []

    def fetch(url, *, method="GET", headers=None, **_k):
        seen.append(headers or {})
        hdrs = [("Content-Type", "text/html")]
        if len(seen) > 1:                      # 두 번째 주소에는 CSP 가 있다
            hdrs.append(("Content-Security-Policy", "default-src 'self'"))
        return Response(url=url, status=200, headers=hdrs, body="<html>ok</html>")
    monkeypatch.setattr(core, "fetch", fetch)
    pts = [Point(method="GET", url="https://sesacedu.store/a", param="", place="path"),
           Point(method="GET", url="https://sesacedu.store/b", param="", place="path")]
    out = header_probe.run(T, pts, {})
    assert {c.title for c in out} == {"보안 헤더·쿠키·CORS 설정 미흡"}   # 빠진 것이 달라도 한 종류
    assert "빠진 것:" in out[0].evidence                                # 무엇이 빠졌는지는 근거에
    assert "Content-Security-Policy" in out[0].evidence


def test_attack_mapping_says_what_the_module_does(app):
    """ATT&CK 은 '이 모듈이 무엇을 하는가' 다 — 결과가 무엇으로 이어질 수 있는가가 아니다.

    11-21 사용자 지적: DAST 에 은닉(TA0005)·권한 상승(TA0004) 모듈이 있을 리 없는데 보드에 떴다.
    인증·인가와 JWT 가 T1548(호스트 권한 제어 악용), 서버 출력 읽기가 T1068(LPE)을 달고 있었다.
    """
    from dashboard import routes
    with app.test_request_context():
        mods = routes._modules()
    host = {"TA0004": "권한 상승", "TA0005": "은닉", "TA0112": "방어 무력화", "TA0003": "지속성",
            "TA0008": "내부 이동", "TA0011": "명령·제어", "TA0040": "영향"}
    bad = [(m.id, a["tactic"], a["technique"]) for m in mods.values()
           for a in m.attack if a["tactic"] in host]
    assert not bad, f"웹 점검 모듈이 호스트 전술을 달고 있다: {bad}"
    assert not [(m.id, a) for m in mods.values() for a in m.attack if a["technique"] == "T1548"]
    # JWT 는 SAML 이 아니다 — 하위 기법이 아니라 상위 T1606 을 쓴다
    jwt = mods["jwt_probe"]
    assert [a["technique"] for a in jwt.attack] == ["T1606"]
