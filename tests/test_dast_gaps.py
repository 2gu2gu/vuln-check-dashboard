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
    assert hit and "60분 전" in hit[0].title
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
    assert c.verdict == "vuln" and ".jsp" in c.title and c.severity == "critical"


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
    assert c.verdict == "vuln" and "X-Api-Version" in c.title
