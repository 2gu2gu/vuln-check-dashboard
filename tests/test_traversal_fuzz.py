# -*- coding: utf-8 -*-
"""자료 경로 조작 퍼징 모듈.

판정이 아니라 **단정하지 않는지**를 주로 본다. 404 를 '없음'으로, 가리지 못한 500 을
'파일'로 적는 순간 보고서가 틀리기 때문이다(2026-11-04 실측 근거).
"""
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from dashboard import cvss, needs
from dashboard.core import Response, Target, ToolResult
from projects.sesacedu.modules import material_traversal_fuzz as mod

T = Target(1, "t", "https://sesacedu.store")


# 모듈은 지도를 그리기 전에 **오라클을 교정한다** — 답을 아는 네 경로가 뜻대로
# 와야 비로소 구조를 그린다(틀리면 일부러 멈춘다). 그래서 가짜 서버도 그 네 경로를
# 실서버와 같게 답해야 한다. 실서버에서 `/etc` 는 디렉터리라 500 이고, `/etc/..` 는
# 상위로 해석돼 또 500 이고, `/etc/passwd/..` 는 ENOTDIR 로 404 다.
#
# pages 가 같은 키를 주면 pages 가 이긴다 — 교정 실패 자체를 보는 테스트는 그렇게
# 일부러 깨뜨린다.
GATES = {"/etc/passwd": 200, "/etc": 500, "/etc/..": 500}
# 교정·깊이 측정에 들어가는 요청 수. 요청 수를 세는 테스트가 이만큼을 빼고 본다.
#   깊이 측정 1건(가짜 서버는 ../ 를 전부 지우므로 1단에서 바로 읽힌다) + 교정 4건
SETUP_REQUESTS = 5


def seeded(pages, default=404):
    """경로별 응답 코드를 흉내 내는 fetch. 보낸 경로를 calls 에 쌓는다.

    pages 의 키는 디코딩한 파일시스템 경로다('/etc/passwd' 꼴).
    """
    calls = []

    def fetch(url, **_kw):
        payload = parse_qs(urlsplit(url).query).get("file", [""])[0]
        once = unquote(payload)          # %25%32%65 → %2e
        twice = unquote(once)            # %2e → .
        path = "/" + twice.replace("../", "").lstrip("/")
        calls.append(path)
        status = pages.get(path, GATES.get(path, default))
        return Response(url=url, status=status, headers=[],
                        body="x" * (10 if status == 200 else 0))

    fetch.calls = calls
    return fetch


def run(monkeypatch, pages, **params):
    fetch = seeded(pages)
    monkeypatch.setattr(mod, "fetch", fetch)
    # 사전은 두 번 읽힌다(씨앗 1단계·이름 2단계). lambda 안에서 pop 하면
    # 첫 번째만 _words 를 받고 두 번째가 기본값으로 떨어진다.
    words = params.pop("_words", None) or WORDS
    body = dict({"mode": "seed", "wordlist": "", "names": "", "limit": "10",
                 "kinds": "yes", "depth": "9", "scheme": "double-full",
                 "lecture": "123"}, **params)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(words), False))
    return mod.run(T, body), fetch


WORDS = ["etc/passwd", "etc/shadow", "etc", "etc/nope-xyz"]


# ── META 규약 ─────────────────────────────────────────────────
def test_cvss_vector_is_valid():
    """벡터가 틀리면 모듈이 등록되지 않는다."""
    assert cvss.score(META_CVSS) == 6.5
    r = cvss.rate(META_CVSS)
    assert r["severity"] == "medium" and r["label"] == "Medium"
    assert r["notion"] == "Medium"          # 노션 CVSS 속성에 그대로 들어간다
    assert r["impact_text"] == "Medium(6.5)"


META_CVSS = mod.META["cvss"]


def test_needs_declares_the_token():
    out = needs.validate(mod.META["needs"])
    kinds = {n["kind"]: n for n in out}
    assert "auth_header" in kinds
    assert kinds["auth_header"]["name"] == "Authorization"
    assert kinds["env"]["required"] is False       # SecLists 는 없어도 돈다


def test_wordlist_param_declares_purpose():
    """purpose 가 있어야 SecLists 가 용도별로 묶여 뜬다."""
    p = [x for x in mod.META["params"] if x["name"] == "wordlist"][0]
    assert p["type"] == "wordlist"
    assert p["purpose"] == "path"


def test_is_active_because_it_sends_many_requests():
    assert mod.META["kind"] == "active"


# ── 오라클 ────────────────────────────────────────────────────
def test_404_is_not_listed_as_a_finding(monkeypatch):
    """404 는 '없음'이 아니라 stat 실패다. 표에 올리지 않는다."""
    r, _ = run(monkeypatch, {"/etc/passwd": 200})
    paths = [row[0] for row in r.rows]
    assert "/etc/passwd" in paths
    assert "/etc/nope-xyz" not in paths


def test_note_warns_that_404_is_not_absence(monkeypatch):
    r, _ = run(monkeypatch, {"/etc/passwd": 200})
    assert "404" in r.note and "탐색 권한" in r.note
    assert "root/.bashrc" in r.note or ".bashrc" in r.note


def test_500_with_dir_parent_is_a_directory(monkeypatch):
    """'<경로>/..' 가 500 이면 들어갈 수 있는 디렉터리다."""
    r, _ = run(monkeypatch, {"/etc": 500, "/etc/..": 500})
    row = [x for x in r.rows if x[0] == "/etc"][0]
    assert row[3] == "디렉터리"


def test_500_with_404_parent_is_not_called_a_file(monkeypatch):
    """ENOTDIR(못 읽는 파일)과 EACCES(못 들어가는 디렉터리)가 같은 404 라 가릴 수 없다."""
    r, _ = run(monkeypatch, {"/etc/shadow": 500, "/etc/shadow/..": 404})
    row = [x for x in r.rows if x[0] == "/etc/shadow"][0]
    assert row[3] == "못 들어감"
    assert row[3] != "파일"
    assert "가리지 못한" in r.note or "가리지" in r.note


def test_kinds_no_skips_the_parent_probe(monkeypatch):
    r, fetch = run(monkeypatch, {"/etc": 500}, kinds="no")
    # 교정은 '/..' 로 오라클을 확인하므로 그 몫은 세지 않는다 — 종류 가리기가
    # 꺼졌는지는 교정 뒤에 '/..' 가 더 가는지로 본다.
    after = fetch.calls[SETUP_REQUESTS:]
    assert not any(p.endswith("/..") for p in after)
    row = [x for x in r.rows if x[0] == "/etc"][0]
    assert row[3] == "미판별"


# ── 모드 ──────────────────────────────────────────────────────
def test_expand_mode_joins_words_under_base(monkeypatch):
    r, fetch = run(monkeypatch, {"/srv/sesacedu/api": 500, "/srv/sesacedu/api/..": 500},
                   mode="expand", base="srv/sesacedu", _words=["api", "web"])
    assert "/srv/sesacedu/api" in fetch.calls
    assert "/srv/sesacedu/web" in fetch.calls
    assert [x for x in r.rows if x[0] == "/srv/sesacedu/api"]


def test_expand_mode_needs_a_base(monkeypatch):
    with pytest.raises(ValueError) as exc:
        run(monkeypatch, {}, mode="expand", base="")
    assert "기준 디렉터리" in str(exc.value)


def test_expand_skips_words_that_are_not_path_pieces(monkeypatch):
    r, fetch = run(monkeypatch, {}, mode="expand", base="opt",
                   _words=["java", "a/b", "..", "ok"])
    assert "/opt/a/b" not in fetch.calls
    assert "/opt/java" in fetch.calls
    assert "건너뛰었습니다" in r.note


# ── 안전장치 ──────────────────────────────────────────────────
def test_stops_on_401_and_says_the_map_is_false(monkeypatch):
    r, _ = run(monkeypatch, {"/etc/passwd": 401})
    assert "401" in r.note
    assert "거짓 지도" in r.note


def test_does_not_record_file_contents(monkeypatch):
    """구조만 본다 — record_body=False 로 보내고 근거에도 내용을 넣지 않는다."""
    seen = {}

    def fetch(url, **kw):
        seen.update(kw)
        return Response(url=url, status=200, headers=[], body="root:x:0:0:")

    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (["etc/passwd"], False))
    r = mod.run(T, {"mode": "seed", "wordlist": "", "limit": "5", "kinds": "no",
                    "depth": "9", "scheme": "double-full", "lecture": "123"})
    assert seen.get("record_body") is False
    for f in r.findings:
        assert "root:x:" not in f.evidence


def test_caps_total_requests(monkeypatch):
    """예산은 사용자가 정하고, 그 안에서 멈춘다."""
    many = ["etc/p%d" % i for i in range(mod.MAX_REQUESTS * 2)]
    r, fetch = run(monkeypatch, {}, kinds="no", limit="99999",
                   budget="300", _words=many)
    assert len(fetch.calls) <= 300
    assert "요청 상한 300건에 닿아 멈췄습니다" in r.note
    # 끊긴 것을 '없다' 로 읽지 않게 적어야 한다
    assert "안 봤다" in r.note


def test_budget_cannot_exceed_the_hard_ceiling(monkeypatch):
    """사용자가 큰 값을 넣어도 절대 상한을 넘지 않는다."""
    many = ["etc/p%d" % i for i in range(mod.MAX_REQUESTS * 3)]
    _, fetch = run(monkeypatch, {}, kinds="no", limit="99999",
                   budget=str(mod.MAX_REQUESTS * 3), _words=many)
    assert len(fetch.calls) <= mod.MAX_REQUESTS


def test_budget_default_covers_the_measured_tree():
    """11-04 실측에서 구조 전체를 그리는 데 1,342 요청이 들었다.

    기본 예산이 그보다 작으면 '한 번 실행으로 같은 지도' 가 성립하지 않는다.
    """
    assert mod.DEFAULT_BUDGET >= 1300
    assert mod.MAX_REQUESTS > mod.DEFAULT_BUDGET


def test_returns_a_tool_result_with_a_tree(monkeypatch):
    r, _ = run(monkeypatch, {"/etc": 500, "/etc/..": 500, "/etc/passwd": 200})
    assert isinstance(r, ToolResult)
    assert r.text.splitlines()[0].strip() == "/"
    assert "passwd" in r.text


def test_only_readable_rows_get_a_drill(monkeypatch):
    r, _ = run(monkeypatch, {"/etc/passwd": 200, "/etc": 500, "/etc/..": 500})
    for row, drill in zip(r.rows, r.drills):
        if row[4] == "읽힘":
            assert drill and "내용 보기" in drill
        else:
            assert drill is None


def test_empty_wordlist_is_refused(monkeypatch):
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: ([], False))
    with pytest.raises(ValueError) as exc:
        mod.run(T, {"mode": "seed", "wordlist": "", "limit": "5", "kinds": "no",
                    "depth": "9", "scheme": "double-full", "lecture": "123"})
    assert "사전" in str(exc.value)


# ── 파이프라인: 한 번 실행으로 끝까지 간다 ───────────────────────────
# 씨앗으로 디렉터리를 확정하고 → 그 디렉터리 아래를 사전으로 넓히고 →
# 500 종류를 가리고 → 트리까지. 사람이 중간에서 결과를 읽고 다시 타이핑하지 않는다.

def pipeline(monkeypatch, pages, seeds, names, **params):
    fetch = seeded(pages)
    monkeypatch.setattr(mod, "fetch", fetch)
    turn = {"n": 0}

    def load(*_a, **_k):
        turn["n"] += 1
        return (list(seeds) if turn["n"] == 1 else list(names)), False

    monkeypatch.setattr(mod.wordlists, "load", load)
    body = dict({"mode": "pipeline", "wordlist": "s", "names": "n", "limit": "50",
                 "kinds": "yes", "depth": "9", "scheme": "double-full",
                 "lecture": "123", "hints": ""}, **params)
    return mod.run(T, body), fetch


DIRS = {"/srv/app": 500, "/srv/app/..": 500,
        "/srv/app/conf": 500, "/srv/app/conf/..": 500,
        "/srv/app/api.env": 200}


def test_stage_two_uses_what_stage_one_found(monkeypatch):
    """핵심 — 2단계 기준 디렉터리를 사람이 적지 않는다. 1단계가 찾은 것을 쓴다."""
    r, fetch = pipeline(monkeypatch, DIRS, seeds=["srv/app", "etc/nope"],
                        names=["conf", "api.env"])
    assert "/srv/app/conf" in fetch.calls and "/srv/app/api.env" in fetch.calls
    # 1단계에서 404 였던 곳 아래로는 넓히지 않는다 — 요청 낭비다
    assert "/etc/nope/conf" not in fetch.calls
    assert [p for p in r.rows if p[0] == "/srv/app/api.env"][0][5] == "확장"


def test_tree_is_drawn_in_the_same_run(monkeypatch):
    r, _ = pipeline(monkeypatch, DIRS, seeds=["srv/app"], names=["conf", "api.env"])
    assert "srv/" in r.text and "api.env" in r.text        # 트리가 같은 실행에서 나온다
    assert "출처" in r.text


def test_stages_are_reported(monkeypatch):
    r, _ = pipeline(monkeypatch, DIRS, seeds=["srv/app"], names=["conf"])
    assert "씨앗" in r.summary and "확장" in r.summary


def test_hints_are_kept_apart(monkeypatch):
    """사람·AI 가 넣은 경로는 '퍼징이 찾았다'로 집계되지 않는다."""
    pages = dict(DIRS, **{"/opt/x+1": 500, "/opt/x+1/..": 500})
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"], names=["conf"], hints="opt/x+1")
    row = [p for p in r.rows if p[0] == "/opt/x+1"][0]
    assert row[5] == "단서(밖에서)"
    assert "밖에서 받아 확인만 함 1개" in r.text
    assert "퍼징이 찾은 것이 아니다" in r.text
    assert "출처가 섞여 있습니다" in r.note
    f = r.findings[0]
    assert "단서로 받아 확인한 것 1개" in f.evidence
    assert "/opt/x+1" not in f.evidence.split("단서로 받아")[0]   # 앞쪽(퍼징 성과)에는 없다


def test_pipeline_without_hints_says_nothing_about_them(monkeypatch):
    r, _ = pipeline(monkeypatch, DIRS, seeds=["srv/app"], names=["conf"])
    assert "단서" not in r.note and "밖에서" not in r.text


def test_budget_is_not_exceeded(monkeypatch):
    r, fetch = pipeline(monkeypatch, DIRS,
                        seeds=["srv/app"] + [f"d{i}" for i in range(500)],
                        names=[f"n{i}" for i in range(500)])
    assert len(fetch.calls) <= mod.MAX_REQUESTS


# ── 수확: 읽은 파일이 다음 경로를 알려 준다 ──────────────────────────
# 사전은 이름을 '맞혀야' 찾지만 설정 파일은 경로를 '적어 놓는다'.
# 사람이 눈으로 하던 일(systemd 유닛에서 JAVA_HOME 읽기)을 모듈 안으로 넣었다.

UNIT = ("[Service]\n"
        "WorkingDirectory=/srv/sesacedu\n"
        "EnvironmentFile=/etc/sesacedu/api.env\n"
        "Environment=JAVA_HOME=/opt/java/jdk-11.0.24+8\n")
ENVFILE = "DB_PASSWORD=hunter2\nAPP_STORAGE_ROOT=/srv/sesacedu/storage\n"


def test_harvest_reads_paths_out_of_a_systemd_unit():
    got = mod.harvest_paths(UNIT)
    assert "srv/sesacedu" in got
    assert "etc/sesacedu/api.env" in got
    assert "opt/java/jdk-11.0.24+8" in got, "버전이 든 이름은 사전에 없다 — 이 길로만 나온다"


def test_harvest_reads_nginx_and_env():
    assert "var/www/x" in mod.harvest_paths("server {\n  root /var/www/x;\n}")
    assert "srv/sesacedu/storage" in mod.harvest_paths(ENVFILE)


def test_harvest_does_not_pick_up_secrets():
    """경로처럼 생기지 않은 값은 가져오지 않는다."""
    got = mod.harvest_paths(ENVFILE)
    assert not any("hunter2" in p for p in got)
    assert not any("jdbc" in p for p in mod.harvest_paths("DB_URL=jdbc:oracle:thin:@10.0.1.5:1521/XE"))


def test_harvest_skips_noise():
    got = mod.harvest_paths("ExecStart=/bin/sh -c 'x > /dev/null'")
    assert "dev/null" not in got and "bin/sh" not in got


def bodies(monkeypatch, pages, seeds, words=("zzz",), **params):
    """경로별로 본문까지 돌려주는 가짜 서버.

    `words` 는 2단계(이름 사전)로 쓸 낱말이다 — 기본값은 아무것도 안 맞는 하나뿐이라,
    넓히기를 보려면 직접 준다.
    """
    calls = []

    def fetch(url, **_kw):
        payload = parse_qs(urlsplit(url).query).get("file", [""])[0]
        path = "/" + unquote(unquote(payload)).replace("../", "").lstrip("/")
        calls.append(path)
        up = path.endswith("/..")
        base = path[:-3] if up else path
        at = pages.get(base, GATES.get(base))
        if at is None:
            return Response(url=url, status=404, headers=[], body="")
        a_file = isinstance(at, str) or at == 200
        if up:
            # 파일 뒤 '/..' 는 ENOTDIR 로 404, 디렉터리는 상위로 해석돼 500.
            # 전에는 파일도 자기 자신을 돌려줘 모든 500 이 디렉터리로 보였다.
            return Response(url=url, status=404 if a_file else 500, headers=[], body="")
        if isinstance(at, str):
            return Response(url=url, status=200, headers=[], body=at)
        return Response(url=url, status=at, headers=[], body="")

    fetch.calls = calls
    monkeypatch.setattr(mod, "fetch", fetch)
    turn = {"n": 0}

    def load(*_a, **_k):
        turn["n"] += 1
        return (list(seeds) if turn["n"] == 1 else list(words)), False

    monkeypatch.setattr(mod.wordlists, "load", load)
    body = dict({"mode": "pipeline", "wordlist": "s", "names": "n", "limit": "50",
                 "kinds": "yes", "depth": "9", "scheme": "double-full",
                 "lecture": "123", "hints": "", "rounds": "2"}, **params)
    return mod.run(T, body), fetch


CHAIN = {"/etc/systemd/system/sesacedu-api.service": UNIT,
         "/etc/sesacedu/api.env": ENVFILE,
         "/srv/sesacedu": 500, "/opt/java/jdk-11.0.24+8": 500,
         "/srv/sesacedu/storage": 500}


def test_harvest_chains_one_seed_into_a_whole_tree(monkeypatch):
    """씨앗 1개 → 유닛 읽음 → 거기 적힌 경로 → 그중 .env 읽음 → 또 그 안의 경로."""
    r, fetch = bodies(monkeypatch, CHAIN, seeds=["etc/systemd/system/sesacedu-api.service"])
    found = {row[0] for row in r.rows}
    assert "/opt/java/jdk-11.0.24+8" in found    # 1바퀴
    assert "/srv/sesacedu/storage" in found      # 2바퀴 — .env 를 읽고 나서야 나온다
    assert "수확" in r.summary
    by = {row[0]: row[5] for row in r.rows}
    assert by["/opt/java/jdk-11.0.24+8"] == "수확"


def test_harvest_can_be_turned_off(monkeypatch):
    r, _ = bodies(monkeypatch, CHAIN, seeds=["etc/systemd/system/sesacedu-api.service"],
                  rounds="0")
    assert "/opt/java/jdk-11.0.24+8" not in {row[0] for row in r.rows}
    assert "수확" not in r.summary


def test_file_contents_never_leave_the_module(monkeypatch):
    """설정 파일에는 자격증명이 섞여 있다. 경로만 쓰고 내용은 버린다."""
    r, _ = bodies(monkeypatch, CHAIN, seeds=["etc/systemd/system/sesacedu-api.service"])
    everywhere = r.text + r.note + str(r.rows) + "".join(f.evidence for f in r.findings)
    assert "hunter2" not in everywhere
    assert "DB_PASSWORD" not in everywhere


def test_harvest_counts_as_the_modules_own_work(monkeypatch):
    """수확은 모듈이 스스로 한 일이다 — 사람이 넣은 '단서' 와 다르다."""
    r, _ = bodies(monkeypatch, CHAIN, seeds=["etc/systemd/system/sesacedu-api.service"])
    assert "퍼징이 스스로 찾음" in r.text
    assert "밖에서 받아" not in r.text


# ── 실측 유닛 파일로 고정 ────────────────────────────────────────────
# 11-04 실서버에서 읽힌 /etc/systemd/system/sesacedu-api.service (546B) 의 모양이다.
# 모의해킹 세션이 **눈으로 읽어 손으로 넣어야 했던** 경로 3개가 여기서 나왔다.
# 그 셋을 수확기가 자동으로 찾아내는지 못박는다.

REAL_UNIT = """[Unit]
Description=SesacEdu API
[Service]
Type=simple
User=sesacedu
WorkingDirectory=/srv/sesacedu/api
EnvironmentFile=/etc/sesacedu/api.env
Environment=JAVA_HOME=/opt/java/jdk-11.0.24+8
Environment=CATALINA_HOME=/opt/apache-tomcat-10.1.1
ExecStart=/opt/apache-tomcat-10.1.1/bin/catalina.sh run
"""


@pytest.mark.parametrize("path, why", [
    ("etc/sesacedu/api.env", "api.env 는 어느 사전에도 없다"),
    ("opt/java/jdk-11.0.24+8", "버전 문자열이 든 이름은 사전에 있을 수 없다"),
    ("opt/apache-tomcat-10.1.1", "같은 이유"),
])
def test_harvests_what_a_person_had_to_read_by_eye(path, why):
    assert path in mod.harvest_paths(REAL_UNIT), why


def test_nested_environment_key_is_unwrapped():
    """Environment=KEY=/path 는 '='가 한 번 더 중첩돼 있다."""
    got = mod.harvest_paths("Environment=JAVA_HOME=/opt/java/jdk-11.0.24+8\n")
    assert "opt/java/jdk-11.0.24+8" in got
    assert not any(p.startswith("JAVA_HOME") for p in got)


def test_harvested_plus_path_survives_the_round_trip():
    """수확한 '+' 경로를 다시 보낼 때 공백으로 읽히면 안 된다(payloads 수정과 한 쌍)."""
    from dashboard.payloads import traversal
    path = next(p for p in mod.harvest_paths(REAL_UNIT) if "+" in p)
    assert "+" not in traversal(path, 9, "double-full")


# ── 찾은 것에 '무엇인지' 를 붙인다 ───────────────────────────────────
# 퍼징은 경로를 찾을 뿐 의미는 모른다. api.env 를 찾아 놓고 크기만 적으면
# 보고서를 읽는 사람이 왜 중요한지 알 수 없다.

def test_known_paths_get_a_description():
    from projects.sesacedu.fs_knowledge import describe
    desc, sev = describe("etc/sesacedu/api.env")
    assert sev == "critical" and "JWT" in desc


def test_guessed_descriptions_are_marked():
    """짐작을 본 것처럼 적으면 보고서가 틀린다."""
    from projects.sesacedu.fs_knowledge import describe
    desc, sev = describe("srv/whatever/secrets.env")
    assert sev == "critical" and desc.endswith("(추정)")
    assert describe("etc/sesacedu/api.env")[0].endswith("(추정)") is False


def test_unknown_path_says_nothing():
    from projects.sesacedu.fs_knowledge import describe
    assert describe("opt/zzz/thing") == ("", "info")


def test_tree_carries_the_descriptions(monkeypatch):
    pages = dict(DIRS, **{"/etc/sesacedu/api.env": 200})
    r, _ = pipeline(monkeypatch, pages, seeds=["etc/sesacedu/api.env"], names=["conf"])
    assert "DB·JWT 서명키" in r.text


def test_sensitive_reads_become_their_own_findings(monkeypatch):
    pages = dict(DIRS, **{"/etc/sesacedu/api.env": 200})
    r, _ = pipeline(monkeypatch, pages, seeds=["etc/sesacedu/api.env"], names=["conf"])
    one = [f for f in r.findings if f.title.startswith("민감 파일 노출")]
    assert one and one[0].severity == "critical"
    assert "/etc/sesacedu/api.env" in one[0].title


def test_min_severity_can_turn_that_off(monkeypatch):
    pages = dict(DIRS, **{"/etc/sesacedu/api.env": 200})
    r, _ = pipeline(monkeypatch, pages, seeds=["etc/sesacedu/api.env"], names=["conf"],
                    min_severity="none")
    assert not [f for f in r.findings if f.title.startswith("민감 파일 노출")]


# ── 추출 규칙: 11-04 실측에서 실제로 수확이 된 형태만 ────────────────
# 모의해킹 세션이 유닛 파일 **하나**에서 손으로 캐낸 것이 5개다.
# 전부 어떤 사전에도 없는 이름이고, /srv/sesacedu/api-data 는 탈출 출발점이었다.

REAL_UNIT5 = """[Unit]
Description=SesacEdu API
[Service]
WorkingDirectory=/srv/sesacedu/api-data
EnvironmentFile=/etc/sesacedu/api.env
Environment=JAVA_HOME=/opt/java/jdk-11.0.24+8
Environment=CATALINA_HOME=/opt/apache-tomcat-10.1.1
Environment=CATALINA_BASE=/srv/sesacedu/api
"""


@pytest.mark.parametrize("path", [
    "srv/sesacedu/api-data",            # WorkingDirectory — 탈출 출발점
    "etc/sesacedu/api.env",             # EnvironmentFile — JWT 서명키가 있던 파일
    "opt/java/jdk-11.0.24+8",           # Environment= 2단
    "opt/apache-tomcat-10.1.1",         # Environment= 2단
    "srv/sesacedu/api",                 # Environment= 2단 (CATALINA_BASE)
])
def test_harvests_all_five_from_one_unit(path):
    assert path in mod.harvest_paths(REAL_UNIT5)


def test_parent_chain_comes_along():
    """경로 하나를 얻으면 부모도 넣는다 — 요청 1건에 디렉터리 하나라 값이 좋다."""
    got = mod.harvest_paths("WorkingDirectory=/srv/sesacedu/api-data\n")
    assert "srv/sesacedu/api-data" in got and "srv/sesacedu" in got


@pytest.mark.parametrize("text, why", [
    ("DB_URL=https://example.com/api/v1", "URL 은 서버 경로가 아니다"),
    ("x=/proc/self/environ", "/proc 은 가상 파일시스템"),
    ("y=/sys/class/net", "/sys 도 가상"),
    ("z=/dev/null", "쓸모없음"),
])
def test_noise_is_filtered(text, why):
    assert mod.harvest_paths(text) == [], why


def test_nginx_keys():
    got = mod.harvest_paths("root /var/www/x;\nalias /srv/static/y;\n"
                            "ssl_certificate_key /etc/ssl/k.pem;\n")
    for p in ("var/www/x", "srv/static/y", "etc/ssl/k.pem"):
        assert p in got


def test_catalina_base_is_substituted():
    """catalina.properties 의 ${catalina.base} 는 유닛에서 얻은 값으로 푼다."""
    got = mod.harvest_paths("common.loader=${catalina.base}/lib",
                            base_hint="/srv/sesacedu/api")
    assert "srv/sesacedu/api/lib" in got
    assert not any("catalina.base" in p for p in got)


def test_reads_the_valuable_files_first():
    """유닛 하나에서 5경로가 나왔다. web.xml 은 크기만 크고 경로가 없다."""
    nodes = [{"path": "/srv/app/WEB-INF/web.xml", "size": 168_000},
             {"path": "/etc/systemd/system/x.service", "size": 546},
             {"path": "/etc/nginx/sites-available/y", "size": 2200},
             {"path": "/var/log/dpkg.log", "size": 59_000}]
    order = [n["path"] for n in mod.harvest_order(nodes)]
    assert order[0].endswith(".service")
    assert "/srv/app/WEB-INF/web.xml" not in order   # 건너뛴다
    assert "/var/log/dpkg.log" not in order


def test_harvest_stops_when_nothing_new(monkeypatch):
    """한 바퀴 돌아 새로 '존재' 가 없으면 멈춘다 — 요청을 아낀다."""
    pages = dict(DIRS, **{"/srv/app/x.service": "EnvironmentFile=/nowhere/zzz.env\n"})
    r, fetch = pipeline(monkeypatch, pages, seeds=["srv/app/x.service"], names=["conf"],
                        rounds="5")
    assert len([c for c in fetch.calls if "nowhere" in c]) <= 2   # 한 번 보고 그만


# ── 오라클 교정 — 지도를 그리기 전에 코드가 뜻을 갖는지 확인한다 ──────────
def blind(monkeypatch, **params):
    """답을 아는 경로마저 404 로 오는 서버. 취약점이 막힌 상태를 흉내 낸다."""
    calls = []

    def fetch(url, **_kw):
        calls.append(url)
        return Response(url=url, status=404, headers=[], body="")

    fetch.calls = calls
    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(WORDS), False))
    body = dict({"mode": "pipeline", "wordlist": "s", "names": "n", "limit": "50",
                 "kinds": "yes", "depth": "9", "scheme": "double-full",
                 "lecture": "123", "hints": ""}, **params)
    return mod.run(T, body), fetch


def test_refuses_to_draw_a_map_when_the_oracle_is_broken(monkeypatch):
    """전부 404 인 서버는 '아무것도 없는 서버' 와 구별되지 않는다 — 멈춰야 한다.

    여기서 지도를 그리면 '빈 서버' 라는 거짓 결과가 보고서에 올라간다.
    """
    r, _ = blind(monkeypatch)
    assert "교정 실패" in r.summary
    assert not r.text                      # 트리를 그리지 않는다
    assert not r.findings                  # 결과도 올리지 않는다
    assert "일부러 멈췄습니다" in r.note
    assert "전부 404" in r.note


def test_broken_oracle_does_not_waste_the_whole_budget(monkeypatch):
    """막힌 걸 알았으면 사전을 다 때리지 않는다."""
    _, fetch = blind(monkeypatch, budget="800")
    assert len(fetch.calls) < 40           # 깊이 측정 + 교정 몫만


def test_calibration_table_shows_which_gate_failed(monkeypatch):
    r, _ = blind(monkeypatch)
    paths = {row[0] for row in r.rows}
    assert "etc/passwd" in paths and "etc/passwd/.." in paths
    wrong = [row for row in r.rows if row[3] == "틀림"]
    assert len(wrong) == 3                 # passwd·etc·etc/.. 가 틀리고, passwd/.. 는 맞음


def test_calibration_checks_the_property_kind_sorting_relies_on():
    """뒤 두 항목이 종류 가리기의 근거다. 빠지면 '디렉터리' 판정이 무근거가 된다."""
    probes = [p for p, _, _ in mod.CALIBRATION]
    assert "etc/.." in probes              # 디렉터리 뒤 '/..' → 500
    assert "etc/passwd/.." in probes       # 파일 뒤 '/..' → 404
    want = dict((p, w) for p, w, _ in mod.CALIBRATION)
    assert want["etc/.."] == mod.EXISTS
    assert want["etc/passwd/.."] == mod.UNSTAT


def test_401_during_calibration_says_the_token_is_the_problem(monkeypatch):
    def fetch(url, **_kw):
        return Response(url=url, status=401, headers=[], body="")

    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(WORDS), False))
    r = mod.run(T, {"mode": "pipeline", "wordlist": "s", "names": "n", "limit": "50",
                    "kinds": "yes", "depth": "auto", "scheme": "double-full",
                    "lecture": "123", "hints": ""})
    assert "401" in r.summary
    assert "거짓 지도" in r.note
    assert not r.text


# ── 올라갈 단계는 재서 쓴다 ───────────────────────────────────
def test_depth_is_measured_not_guessed(monkeypatch):
    """`auto` 면 1단부터 올려 가며 처음 읽히는 단계를 쓴다."""
    seen = []

    def fetch(url, **_kw):
        payload = parse_qs(urlsplit(url).query).get("file", [""])[0]
        once = unquote(unquote(payload))
        up = once.count("../")
        rest = "/" + once.replace("../", "").lstrip("/")
        seen.append((up, rest))
        # 3단 이상 올라가야 최상위에 닿는 서버
        if up < 3:
            return Response(url=url, status=404, headers=[], body="")
        status = GATES.get(rest, 404)
        return Response(url=url, status=status, headers=[],
                        body="x" * (10 if status == 200 else 0))

    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (["etc/passwd"], False))
    r = mod.run(T, {"mode": "seed", "wordlist": "s", "names": "", "limit": "10",
                    "kinds": "no", "depth": "auto", "scheme": "double-full",
                    "lecture": "123", "hints": ""})
    assert "교정 실패" not in r.summary          # 재서 맞췄으니 교정도 통과한다
    assert "직접 재서 3 를 썼습니다" in r.note
    # 1·2 단을 시험한 뒤 3 을 골랐고, 그 뒤 요청은 전부 3 단이다
    tried = [up for up, _ in seen[:3]]
    assert tried == [1, 2, 3]
    assert all(up == 3 for up, _ in seen[3:])


def test_explicit_depth_is_honoured(monkeypatch):
    """숫자를 적으면 재지 않고 그 값을 쓴다."""
    r, fetch = run(monkeypatch, {"/etc/passwd": 200}, depth="7")
    assert "직접 재서" not in r.note
    assert fetch.calls                       # 측정 몫 없이 바로 때린다


def test_a_fixed_depth_that_is_too_small_is_caught_by_calibration(monkeypatch):
    """고정값이 모자라면 전부 404 다 — 그래서 교정이 먼저 잡는다."""
    def fetch(url, **_kw):
        payload = parse_qs(urlsplit(url).query).get("file", [""])[0]
        if unquote(unquote(payload)).count("../") < 5:
            return Response(url=url, status=404, headers=[], body="")
        return Response(url=url, status=200, headers=[], body="x")

    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(WORDS), False))
    r = mod.run(T, {"mode": "seed", "wordlist": "s", "names": "", "limit": "10",
                    "kinds": "no", "depth": "2", "scheme": "double-full",
                    "lecture": "123", "hints": ""})
    assert "교정 실패" in r.summary
    assert "올라갈 단계가 모자라거나" in r.note


# ── 어느 디렉터리부터 넓힐지 ──────────────────────────────────
# 11-04 실측에서 사람이 디렉터리 40곳 중 10곳만 넓혔고(743요청) 적중은 5곳에서 났다.
# 아래는 그 실측 표에서 뽑은 것이다 — 규칙이 사람의 선택을 재현해야 한다.
MEASURED_HITS = ["srv/sesacedu", "srv/sesacedu/api", "srv/sesacedu/api/conf",
                 "srv/sesacedu/web", "srv/sesacedu/web/conf"]
MEASURED_SKIPPED = ["etc/nginx", "etc/systemd/system", "var/log", "etc/letsencrypt",
                    "var/log/nginx", "var/www"]
# 씨앗 사전이 그 아래를 적어 둔 곳 — 사전이 할 말을 이미 했다
SEEDS_SAMPLE = {
    "etc/nginx/nginx.conf", "etc/nginx/sites-available/default",
    "etc/systemd/system/sesacedu-api.service", "var/log/syslog",
    "var/log/nginx/access.log", "etc/letsencrypt/renewal/sesacedu.store.conf",
    "var/www/html/index.html", "srv/sesacedu",
}
HARVEST_SAMPLE = {"srv/sesacedu/api", "srv/sesacedu/api-data",
                  "opt/apache-tomcat-10.1.1", "opt/java"}


def _as_dirs(paths):
    return [{"path": "/" + p, "kind": mod.DIR, "source": mod.SEED} for p in paths]


def test_ranking_puts_the_measured_hits_first():
    """적중이 난 다섯 곳이 전부 앞에 서야 한다 — 예산이 끊겨도 살아남게."""
    order = mod.rank_dirs(_as_dirs(MEASURED_HITS + MEASURED_SKIPPED),
                          SEEDS_SAMPLE, HARVEST_SAMPLE)
    head = order[:len(MEASURED_HITS)]
    assert set(head) == set(MEASURED_HITS), order


def test_ranking_defers_dirs_the_seed_list_already_covers():
    """씨앗이 그 아래를 적어 둔 곳은 더 때려도 새로 나올 것이 적다."""
    order = mod.rank_dirs(_as_dirs(MEASURED_SKIPPED + ["srv/sesacedu/api"]),
                          SEEDS_SAMPLE, HARVEST_SAMPLE)
    assert order[0] == "srv/sesacedu/api"
    assert order.index("etc/nginx") > order.index("srv/sesacedu/api")


def test_ranking_never_drops_a_dir():
    """순위는 순서만 바꾼다. 빼는 것은 예산이 하고, 뺀 것은 결과에 적는다."""
    everything = MEASURED_HITS + MEASURED_SKIPPED
    order = mod.rank_dirs(_as_dirs(everything), SEEDS_SAMPLE, HARVEST_SAMPLE)
    assert sorted(order) == sorted(everything)


def test_ranking_prefers_harvested_territory():
    """수확이 알려 준 경로 아래가 이 서버만의 영역이다."""
    order = mod.rank_dirs(_as_dirs(["opt/java", "opt/zzz"]), set(), {"opt/java"})
    assert order[0] == "opt/java"


def test_ranking_prefers_shallow_dirs():
    """얕은 곳이 자식이 많다."""
    order = mod.rank_dirs(_as_dirs(["a/b/c/d", "a/b", "a/b/c"]), set(), set())
    assert order == ["a/b", "a/b/c", "a/b/c/d"]


# ── 넓히기는 고른 곳에 사전을 통째로 준다 ─────────────────────
def test_expansion_gives_a_chosen_dir_the_whole_name_list(monkeypatch):
    """전에는 찾은 디렉터리 전부에 `남은예산//2//곳수` 만큼만 줬다.

    디렉터리 40곳이 나오면 한 곳에 이름 2개가 돌아가 **아무것도 안 걸렸다.**
    이 테스트가 그 회귀를 막는다.
    """
    names = ["n%02d" % i for i in range(40)] + ["conf"]
    pages = {"/srv/app": 500, "/srv/app/..": 500,
             "/srv/app/conf": 500, "/srv/app/conf/..": 500}
    _, fetch = pipeline(monkeypatch, pages, seeds=["srv/app"], names=names,
                        budget="900", limit="999")
    under_app = [c for c in fetch.calls if c.startswith("/srv/app/")
                 and not c.endswith("/..")]
    assert len(under_app) >= 40, under_app
    assert "/srv/app/conf" in under_app       # 목록 끝에 있어도 닿는다


def test_expansion_loops_into_what_it_just_found(monkeypatch):
    """한 번만 넓히면 `conf` 는 찾아도 그 **안**은 못 본다.

    conf 는 app 을 넓힌 뒤에야 생기는 대상이라, 돌지 않으면 영원히 안 열린다.
    """
    pages = {"/srv/app": 500, "/srv/app/..": 500,
             "/srv/app/conf": 500, "/srv/app/conf/..": 500,
             "/srv/app/conf/server.xml": 200}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"],
                    names=["conf", "server.xml"], budget="900")
    found = {row[0] for row in r.rows}
    assert "/srv/app/conf" in found
    assert "/srv/app/conf/server.xml" in found     # 2바퀴째에 나온다


def test_expanded_dirs_are_named_in_the_note(monkeypatch):
    """어디를 넓혔는지 적어야, 안 넓힌 곳을 '없다' 로 읽지 않는다."""
    pages = {"/srv/app": 500, "/srv/app/..": 500,
             "/srv/app/conf": 500, "/srv/app/conf/..": 500}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"], names=["conf"],
                    budget="900")
    assert "넓힌 곳" in r.note
    assert "srv/app" in r.note


def test_stops_itself_when_nothing_new_turns_up(monkeypatch):
    """예산이 남아도 더 안 나오면 멈춘다 — 끊긴 것과 구별되게 적는다."""
    pages = {"/srv/app": 500, "/srv/app/..": 500,
             "/srv/app/conf": 500, "/srv/app/conf/..": 500}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"], names=["conf"],
                    budget="900")
    assert "스스로 멈췄습니다" in r.note
    assert "요청 상한" not in r.note


# ── 이름 묶음을 디렉터리 성격에 맞춰 가른다 ───────────────────
# 11-06 1차 실행에서 159개를 한 곳에 전부 보내 8곳에 1,272요청을 쓰고 예산이 바닥났다.
# srv·opt 아래 31개를 그렇게 놓쳤다.
MIXED = ["webapps", "conf", "lib", "server.xml", "context.xml", "web.xml"]


def test_conf_dir_gets_file_names_first():
    """`conf` 아래에 있는 것은 설정 파일이다."""
    first = mod._names_for("srv/sesacedu/api/conf", MIXED, 0)
    assert set(first) == {"server.xml", "context.xml", "web.xml"}


def test_app_root_gets_dir_names_first():
    """배포 루트 아래에 있는 것은 디렉터리다."""
    first = mod._names_for("srv/sesacedu/api", MIXED, 0)
    assert set(first) == {"webapps", "conf", "lib"}


def test_the_other_group_is_deferred_not_dropped():
    """점 유무는 완벽한 기준이 아니다(`sites-available`). 그래서 버리지 않고 미룬다."""
    for root in ("srv/app/conf", "srv/app"):
        a = mod._names_for(root, MIXED, 0)
        b = mod._names_for(root, MIXED, 1)
        assert sorted(a + b) == sorted(MIXED)
        assert not set(a) & set(b)


def test_kind_sorting_happens_right_after_harvest(monkeypatch):
    """수확이 찾은 디렉터리가 **같은 바퀴**의 넓히기 순위에 들어가야 한다.

    가리기를 바퀴 머리에서 하면 한 바퀴 늦어, 그 사이 예산이 엉뚱한 곳으로 간다.
    """
    pages = {
        # 씨앗 하나 — 유닛. 여기서 배포 경로가 나온다
        "/etc/systemd/system/x.service": "Environment=CATALINA_BASE=/srv/deploy\n",
        "/srv/deploy": 500, "/srv/deploy/..": 500,
        "/srv/deploy/webapps": 500, "/srv/deploy/webapps/..": 500,
        # 씨앗이 아는 곳 — 순위에서 뒤로 가야 한다
        "/etc/nginx/snippets": 500, "/etc/nginx/snippets/..": 500,
    }
    r, fetch = bodies(monkeypatch, pages,
                      seeds=["etc/systemd/system/x.service", "etc/nginx/snippets"],
                      words=["webapps"], budget="200")
    found = {row[0] for row in r.rows}
    # 수확으로 /srv/deploy 를 얻고, 같은 바퀴에 디렉터리로 가린 뒤 넓혀 webapps 를 찾는다
    assert "/srv/deploy" in found
    assert "/srv/deploy/webapps" in found, sorted(found)


def test_reserve_keeps_budget_for_kind_sorting(monkeypatch):
    """넓히기가 예산을 다 먹으면 500 이 '미판별' 로 남아 트리가 반쪽이 된다."""
    names = ["n%03d" % i for i in range(300)]
    pages = {"/srv/app": 500, "/srv/app/..": 500}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"], names=names,
                    budget="200", limit="999")
    row = [x for x in r.rows if x[0] == "/srv/app"][0]
    assert row[3] == "디렉터리"          # 미판별로 남지 않았다


# ── JSP 앱 안쪽으로 들어가기 ──────────────────────────────────
# 풀린 WAR 안의 페이지 이름은 사전으로 맞힐 수 없다(`detail.jsp`). 그런데 앱이
# 스스로 적어 둔다 — web.xml 의 welcome-file·jsp-file 과 JSP 의 include 줄.
APP_WEB_XML = """<?xml version="1.0" encoding="UTF-8"?>
<web-app>
  <welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
  <servlet>
    <servlet-name>detail</servlet-name>
    <jsp-file>/lecture/detail.jsp</jsp-file>
  </servlet>
</web-app>
"""

INDEX_JSP = """<%@ include file="common/header.jspf" %>
<a href="lecture/detail.jsp?lid=123">보기</a>
<jsp:include page="/common/nav.jsp" />
<%@ include file="../outside.jsp" %>
"""


def test_web_xml_gives_up_its_jsp_names():
    """`/lecture/detail.jsp` 는 **앱 뿌리** 기준이다 — 파일시스템 최상위가 아니다."""
    got = mod.harvest_jsp(APP_WEB_XML, "srv/sesacedu/web/webapps/ROOT/WEB-INF")
    assert "srv/sesacedu/web/webapps/ROOT/lecture/detail.jsp" in got
    assert "srv/sesacedu/web/webapps/ROOT/index.jsp" in got
    # 최상위로 붙이면 안 된다
    assert "lecture/detail.jsp" not in got


def test_jsp_include_is_resolved_against_its_own_folder():
    """`include file="common/header.jspf"` 는 그 JSP 가 있는 폴더 기준이다."""
    got = mod.harvest_jsp(INDEX_JSP, "srv/app/webapps/ROOT")
    assert "srv/app/webapps/ROOT/common/header.jspf" in got
    assert "srv/app/webapps/ROOT/lecture/detail.jsp" in got
    assert "srv/app/webapps/ROOT/common/nav.jsp" in got      # 앞에 / → 앱 뿌리


def test_jsp_harvest_drops_dot_dot_refs():
    """`../outside.jsp` 는 올라가기와 섞여 경로가 어긋난다."""
    got = mod.harvest_jsp(INDEX_JSP, "srv/app/webapps/ROOT")
    assert not any(".." in p for p in got)
    # `../outside.jsp` 자체는 버린다. 이름만 주워 앱 뿌리에 붙여 보는 것은 **추측**이고,
    # 404 가 와도 해롭지 않다 — 다만 '..' 가 든 경로를 그대로 보내지는 않는다.
    assert "srv/app/webapps/ROOT/../outside.jsp" not in got


def test_webapp_root_is_found_from_web_inf():
    assert mod._webapp_root("srv/a/webapps/ROOT/WEB-INF") == "/srv/a/webapps/ROOT"
    assert mod._webapp_root("srv/a/webapps/ROOT/WEB-INF/classes") == "/srv/a/webapps/ROOT"
    assert mod._webapp_root("srv/a/webapps/ROOT") == "/srv/a/webapps/ROOT"


def test_app_web_xml_is_harvested_but_the_tomcat_one_is_not():
    """이름이 아니라 **크기**로 가른다.

    톰캣 전역 `conf/web.xml`(168KB)에는 경로가 없고 비용만 크다. 앱 자신의
    `WEB-INF/web.xml` 은 작고 페이지 이름을 적어 둔다 — 이름으로 web.xml 을 통째로
    건너뛰면 JSP 앱 안쪽으로 들어가는 길이 막힌다.
    """
    nodes = [
        {"path": "/srv/sesacedu/web/conf/web.xml", "size": 168_000},
        {"path": "/srv/sesacedu/web/webapps/ROOT/WEB-INF/web.xml", "size": 2_400},
    ]
    order = [n["path"] for n in mod.harvest_order(nodes)]
    assert "/srv/sesacedu/web/webapps/ROOT/WEB-INF/web.xml" in order
    assert "/srv/sesacedu/web/conf/web.xml" not in order


def test_harvest_chains_into_a_jsp_app(monkeypatch):
    """유닛 → 배포 뿌리 → webapps → ROOT → WEB-INF → web.xml → 페이지 이름.

    한 실행에서 여기까지 가야 'JSP 가 돌는 그 밑까지' 트리가 그려진다.
    """
    pages = {
        "/etc/systemd/system/web.service":
            "Environment=CATALINA_BASE=/srv/sesacedu/web\n",
        "/srv/sesacedu/web": 500,
        "/srv/sesacedu/web/webapps": 500,
        "/srv/sesacedu/web/webapps/ROOT": 500,
        "/srv/sesacedu/web/webapps/ROOT/WEB-INF": 500,
        "/srv/sesacedu/web/webapps/ROOT/WEB-INF/web.xml": APP_WEB_XML,
        "/srv/sesacedu/web/webapps/ROOT/lecture": 500,
        "/srv/sesacedu/web/webapps/ROOT/lecture/detail.jsp": "<html>ok</html>",
    }
    r, _ = bodies(monkeypatch, pages, seeds=["etc/systemd/system/web.service"],
                  words=["webapps", "ROOT", "WEB-INF", "web.xml"],
                  budget="900", rounds="6")
    found = {row[0] for row in r.rows}
    for want in ("/srv/sesacedu/web/webapps",
                 "/srv/sesacedu/web/webapps/ROOT",
                 "/srv/sesacedu/web/webapps/ROOT/WEB-INF",
                 "/srv/sesacedu/web/webapps/ROOT/WEB-INF/web.xml",
                 "/srv/sesacedu/web/webapps/ROOT/lecture/detail.jsp"):
        assert want in found, (want, sorted(found))
    # 사전에 없는 이름이라 출처는 '수확' 이어야 한다
    by = {row[0]: row[5] for row in r.rows}
    assert by["/srv/sesacedu/web/webapps/ROOT/lecture/detail.jsp"] == "수확"


# ── 앱 전체 한도와 모듈 예산 ──────────────────────────────────
# 앱에도 요청 한도가 있다(`DASH_MAX_REQUESTS`). 모듈 예산이 그보다 크면 보내는 쪽에서
# BudgetExceeded 가 올라와 **실행이 깨지고 지도가 아예 안 나온다.** 화면에서만 터지고
# 테스트는 통과하는 자리였다(11-06).
def test_budget_is_clamped_to_the_app_ceiling(app, monkeypatch):
    app.config["MAX_REQUESTS"] = 300
    with app.app_context():
        fetch = seeded({"/etc/passwd": 200})
        monkeypatch.setattr(mod, "fetch", fetch)
        many = ["etc/p%d" % i for i in range(5000)]
        monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(many), False))
        r = mod.run(T, {"mode": "seed", "wordlist": "s", "names": "", "limit": "99999",
                        "kinds": "no", "depth": "9", "scheme": "double-full",
                        "lecture": "123", "hints": "", "budget": "3000"})
    assert len(fetch.calls) < 300
    assert "줄였습니다" in r.note
    assert "DASH_MAX_REQUESTS" in r.note


def test_no_clamp_message_when_the_app_allows_it(app, monkeypatch):
    app.config["MAX_REQUESTS"] = 9000
    with app.app_context():
        fetch = seeded({"/etc/passwd": 200})
        monkeypatch.setattr(mod, "fetch", fetch)
        monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(WORDS), False))
        r = mod.run(T, {"mode": "seed", "wordlist": "s", "names": "", "limit": "10",
                        "kinds": "no", "depth": "9", "scheme": "double-full",
                        "lecture": "123", "hints": "", "budget": "500"})
    assert "줄였습니다" not in r.note


def test_the_app_default_ceiling_fits_a_whole_map(app):
    """기본 설정 그대로 화면에서 눌렀을 때 트리가 반쪽이 되면 안 된다."""
    from dashboard import create_app
    fresh = create_app({"TESTING": True})
    assert fresh.config["MAX_REQUESTS"] >= mod.DEFAULT_BUDGET


# ── 일거리를 네 칸으로 — 배포 영역을 먼저 끝까지 ──────────────
def test_declared_tier_tells_inside_from_outside():
    inside = mod._declared_tier({"srv/sesacedu/api", "/opt/java"})
    assert inside("srv/sesacedu/api")
    assert inside("srv/sesacedu/api/conf")
    assert inside("opt/java/jdk-11.0.24+8")
    assert not inside("etc/cron.daily")
    assert not inside("srv/sesacedu")          # 선언된 것의 **부모**는 안이 아니다


def test_deployment_area_is_expanded_before_os_dirs(monkeypatch):
    """`etc/cron.*`·`usr/sbin` 이 배포 영역보다 먼저 예산을 먹으면 안 된다.

    11-06 3차 실행에서 넓힌 24곳 중 15곳이 OS 폴더였고 2,592요청을 썼는데
    `api/conf`·`web/conf` 는 끝까지 안 열렸다.
    """
    pages = {
        "/etc/systemd/system/x.service": "Environment=CATALINA_BASE=/srv/deploy\n",
        "/srv/deploy": 500,
        "/srv/deploy/conf": 500,
        "/srv/deploy/conf/server.xml": "<Server/>",
        # 씨앗이 찾는 OS 폴더 — 뒤로 가야 한다
        "/etc/cron.d": 500,
        "/usr/sbin": 500,
    }
    r, _ = bodies(monkeypatch, pages,
                  seeds=["etc/systemd/system/x.service", "etc/cron.d", "usr/sbin"],
                  words=["conf", "server.xml"], budget="400", rounds="4")
    import re
    m = re.search(r"넓힌 곳: ([^*]+)", r.note)
    assert m, r.note
    grown = [x.strip() for x in m.group(1).split(",")]
    assert grown[0] == "srv/deploy", grown
    # conf 가 OS 폴더보다 앞에 서야 한다
    assert "srv/deploy/conf" in grown
    assert grown.index("srv/deploy/conf") < min(
        [grown.index(x) for x in grown if x.startswith(("etc/", "usr/"))] or [99])
    assert "/srv/deploy/conf/server.xml" in {row[0] for row in r.rows}


def test_round_limit_is_not_reported_as_nothing_left(monkeypatch):
    """바퀴 상한을 다 쓴 것과 '더 나올 것이 없는' 것은 다르다.

    섞어 적으면 안 넓힌 디렉터리를 '없다' 로 읽는다.
    """
    monkeypatch.setattr(mod, "MAX_ROUNDS", 2)
    pages = {
        "/etc/systemd/system/x.service": "Environment=CATALINA_BASE=/srv/d\n",
        "/srv/d": 500, "/srv/d/a": 500, "/srv/d/a/b": 500, "/srv/d/a/b/c": 500,
    }
    r, _ = bodies(monkeypatch, pages, seeds=["etc/systemd/system/x.service"],
                  words=["a", "b", "c"], budget="500", rounds="3")
    assert "바퀴 상한" in r.note
    assert "스스로 멈췄습니다" not in r.note
    assert "뜻이 **아닙니다**" in r.note


def test_running_out_of_requests_is_never_reported_as_nothing_left(monkeypatch):
    """예비분에 걸려 멈춘 것을 '더 안 나왔다' 로 적으면 안 본 곳을 '없다' 로 읽는다.

    11-06 4차 실행에서 실제로 그렇게 보고됐다 — 148건을 남기고 `web/webapps` 를
    안 넓혔는데 "새로 찾은 것이 없어 스스로 멈췄습니다" 라고 적었다.
    """
    names = ["n%03d" % i for i in range(200)]
    pages = {"/srv/app": 500, "/srv/app/..": 500,
             "/srv/app/n001": 500, "/srv/app/n001/..": 500}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"], names=names,
                    budget="120", limit="999")
    # 예산 때문에 멈춘 것은 두 가지다 — 완전히 바닥난 경우('요청 상한')와 가리기
    # 예비분에 걸린 경우('요청이 모자라'). **어느 쪽이든** 안 본 곳을 '없다' 로
    # 적어서는 안 되고, '더 안 나왔다' 고 말해서도 안 된다.
    assert ("요청 상한" in r.note) or ("요청이 모자라" in r.note), r.note
    assert "안 봤다" in r.note
    assert "스스로 멈췄습니다" not in r.note


def test_the_reserve_is_what_is_actually_needed_not_a_fixed_share(monkeypatch):
    """고정 비율로 남기면 예산이 묶인 채 디렉터리가 안 열린다.

    남길 것은 '아직 안 가린 노드 수' 다 — 그만큼이면 트리가 반쪽이 되지 않는다.
    """
    names = ["n%03d" % i for i in range(60)]
    pages = {"/srv/app": 500, "/srv/app/..": 500,
             "/srv/app/n000": 500, "/srv/app/n000/..": 500,
             "/srv/app/n000/n001": 500, "/srv/app/n000/n001/..": 500}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"], names=names,
                    budget="400", limit="999")
    found = {row[0] for row in r.rows}
    # 두 단계 아래까지 닿아야 한다 — 고정 비율이면 여기서 끊겼다
    assert "/srv/app/n000/n001" in found, sorted(found)
    # 그러면서도 종류는 전부 가려져 있어야 한다
    for row in r.rows:
        assert row[3] != "미판별", row


# ── 설치본과 배포물을 가른다 ──────────────────────────────────
# `*_HOME` 은 제품을 깐 자리이고 그 안은 tarball 이 넣어 준 것이다. 톰캣이 바로 이
# 구분을 쓴다 — CATALINA_HOME = 설치본 · CATALINA_BASE = 이 인스턴스.
UNIT_BOTH = """[Service]
Environment=JAVA_HOME=/opt/java/jdk-11.0.24+8
Environment=CATALINA_HOME=/opt/apache-tomcat-10.1.1
Environment=CATALINA_BASE=/srv/sesacedu/web
WorkingDirectory=/srv/sesacedu/web
EnvironmentFile=/etc/sesacedu/api.env
"""


def test_install_trees_are_still_harvested():
    """JDK·톰캣 설치 경로 자체는 찾아야 한다 — 버전이 보고서에 들어간다."""
    got = mod.harvest_paths(UNIT_BOTH)
    assert "opt/java/jdk-11.0.24+8" in got
    assert "opt/apache-tomcat-10.1.1" in got


def test_only_the_deployment_tree_counts_as_territory_to_widen():
    """설치본 안쪽은 넓힐 곳 순위에서 뒤로 간다.

    11-06 5차 실행에서 이 구분이 없어 `opt/apache-tomcat-10.1.1/webapps/{docs,
    examples,manager}` 와 `opt/java/.../lib/server` 가 예산을 먹고, 정작
    `web/webapps/ROOT/WEB-INF` 는 못 열렸다.
    """
    roots = mod.harvest_declared(UNIT_BOTH)
    assert "srv/sesacedu/web" in roots          # CATALINA_BASE · WorkingDirectory
    assert "etc/sesacedu" in roots              # EnvironmentFile 의 부모
    assert "opt/java/jdk-11.0.24+8" not in roots        # JAVA_HOME
    assert "opt/apache-tomcat-10.1.1" not in roots      # CATALINA_HOME


def test_the_deployment_tree_is_widened_before_the_install_tree(monkeypatch):
    pages = {
        "/etc/systemd/system/w.service": UNIT_BOTH,
        "/srv/sesacedu/web": 500,
        "/srv/sesacedu/web/webapps": 500,
        "/opt/apache-tomcat-10.1.1": 500,
        "/opt/apache-tomcat-10.1.1/webapps": 500,
    }
    r, _ = bodies(monkeypatch, pages, seeds=["etc/systemd/system/w.service"],
                  words=["webapps"], budget="300", rounds="4")
    import re
    m = re.search(r"넓힌 곳: ([^*]+)", r.note)
    assert m, r.note
    grown = [x.strip() for x in re.sub(r"\d+바퀴.*", "", m.group(1)).split(",") if x.strip()]
    assert "srv/sesacedu/web" in grown
    deploy = min(i for i, x in enumerate(grown) if x.startswith("srv/"))
    install = [i for i, x in enumerate(grown) if x.startswith("opt/")]
    if install:
        assert deploy < min(install), grown


def test_stock_key_rule_is_about_the_key_not_the_path():
    """경로 글자가 아니라 **키 이름**으로 가른다 — /opt 라서 거르는 것이 아니다."""
    assert mod._STOCK_KEY.search("JAVA_HOME")
    assert mod._STOCK_KEY.search("CATALINA_HOME")
    assert mod._STOCK_KEY.search("app.home")
    assert not mod._STOCK_KEY.search("CATALINA_BASE")
    assert not mod._STOCK_KEY.search("WorkingDirectory")
    assert not mod._STOCK_KEY.search("EnvironmentFile")


# ── 화면 칸에서 오는 글자를 방어적으로 읽는다 ─────────────────
# 숫자 칸이 자유 입력이라 `Auto`·`6.0`·`1e3`·`abc` 가 그대로 들어온다. 전에는
# `int()` 가 ValueError 를 던져 **실행이 깨지고 지도가 아예 안 나왔다**(11-06 검수).
@pytest.mark.parametrize("raw", ["Auto", "AUTO", "auto", "", "abc", "-5", "1e3", "6.0"])
def test_any_depth_input_is_survivable(monkeypatch, raw):
    r, _ = run(monkeypatch, {"/etc/passwd": 200}, depth=raw)
    assert isinstance(r, ToolResult)                 # 터지지 않는다
    assert "교정 실패" not in r.summary               # 그러고도 지도를 그린다


@pytest.mark.parametrize("raw", ["Auto", "AUTO", "abc", "", "  "])
def test_unparsable_depth_falls_back_to_measuring(monkeypatch, raw):
    """숫자가 아니면 재는 쪽으로 간다 — 터뜨리는 것보다 안전하다.

    `1e3`·`6.0` 은 숫자로 읽어 쓴다(상한 안으로 줄인다) — 여기 넣지 않는다.
    """
    r, _ = run(monkeypatch, {"/etc/passwd": 200}, depth=raw)
    assert "직접 재서" in r.note


def test_a_real_number_is_still_honoured(monkeypatch):
    r, _ = run(monkeypatch, {"/etc/passwd": 200}, depth="6.0")
    assert "직접 재서" not in r.note                  # 6 으로 읽는다


@pytest.mark.parametrize("field,raw", [
    ("budget", "abc"), ("budget", ""), ("budget", "-1"), ("budget", "99999999"),
    ("limit", "abc"), ("limit", "0"), ("limit", "-3"),
    ("rounds", "abc"), ("rounds", "-2"), ("rounds", "3.7"),
])
def test_any_number_field_is_survivable(monkeypatch, field, raw):
    r, _ = run(monkeypatch, {"/etc/passwd": 200}, **{field: raw})
    assert isinstance(r, ToolResult)


def test_as_int_clamps_and_falls_back():
    assert mod._as_int("abc", 7) == 7
    assert mod._as_int("", 7) == 7
    assert mod._as_int(None, 7) == 7
    assert mod._as_int("6.0", 7) == 6
    assert mod._as_int("1e3", 7, high=100) == 100
    assert mod._as_int("-5", 7, low=0) == 0
    assert mod._as_int("  12  ", 7) == 12


def test_expanded_dirs_is_recorded_even_when_the_first_group_is_empty(monkeypatch):
    """점 있는 이름만 든 사전이면 배포 루트의 1차 묶음이 빈다.

    그래도 2차에서 실제로 넓혔으면 '넓힌 곳' 에 적혀야 한다 — 안 적으면 보고가
    실제보다 적게 보인다(11-06 검수).
    """
    pages = {"/srv/app": 500, "/srv/app/..": 500, "/srv/app/server.xml": 200}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/app"],
                    names=["server.xml", "web.xml"], budget="900")
    assert mod._names_for("srv/app", ["server.xml", "web.xml"], 0) == []
    assert "넓힌 곳" in r.note and "srv/app" in r.note
    assert "/srv/app/server.xml" in {row[0] for row in r.rows}


# ── 11-06 검수에서 나온 것 ────────────────────────────────────
# 전부 '테스트가 비어 있던 자리' 였다. 코드가 틀린 것보다, 틀렸는지 물어보지
# 않았던 것이 문제였다.

def walled(monkeypatch, cut_after, cut_status, **params):
    """정상으로 답하다가 cut_after 번째부터 벽을 세우는 서버.

    WAF·속도 제한·탈출 검사가 도중에 켜지는 상황이다.
    """
    pages = {"/srv/app": 500, "/srv/app/conf": 500,
             "/srv/app/conf/server.xml": 200, "/srv/app/webapps": 500,
             "/srv/app/webapps/ROOT": 500}
    calls = []

    def fetch(url, **_kw):
        payload = parse_qs(urlsplit(url).query).get("file", [""])[0]
        path = "/" + unquote(unquote(payload)).replace("../", "").lstrip("/")
        calls.append(path)
        if len(calls) > cut_after:
            return Response(url=url, status=cut_status, headers=[], body="")
        up = path.endswith("/..")
        base = path[:-3] if up else path
        at = pages.get(base, GATES.get(base))
        if at is None:
            return Response(url=url, status=404, headers=[], body="")
        if up:
            return Response(url=url, status=404 if at == 200 else 500, headers=[], body="")
        return Response(url=url, status=at, headers=[], body="x" * (10 if at == 200 else 0))

    fetch.calls = calls
    monkeypatch.setattr(mod, "fetch", fetch)
    turn = {"n": 0}

    def load(*_a, **_k):
        turn["n"] += 1
        return (["srv/app"] if turn["n"] == 1
                else ["conf", "webapps", "ROOT", "server.xml"]), False

    monkeypatch.setattr(mod.wordlists, "load", load)
    body = dict({"mode": "pipeline", "wordlist": "s", "names": "n", "limit": "999",
                 "kinds": "yes", "depth": "9", "scheme": "double-full",
                 "lecture": "123", "hints": "", "rounds": "2", "budget": "400"}, **params)
    return mod.run(T, body), fetch


@pytest.mark.parametrize("wall", [403, 404, 429])
def test_a_wall_mid_run_is_not_reported_as_a_complete_map(monkeypatch, wall):
    """시작 교정 한 번이 수천 요청을 보증하지는 못한다.

    검수 재현: 400요청 중 18건만 쓰고 3노드만 그렸는데 결과는 "교정 4/4 통과 ·
    새로 찾은 것이 없어 스스로 멈췄습니다" 였다. 잘린 지도가 완전한 지도로 보고됐다.
    """
    r, _ = walled(monkeypatch, cut_after=12, cut_status=wall)
    assert "검증되지 않았습니다" in r.note, r.note
    assert "'없다'로 읽지 마세요" in r.note
    assert "스스로 멈췄습니다" not in r.note


def test_without_a_wall_the_end_calibration_is_reported_as_a_pass(monkeypatch):
    r, _ = walled(monkeypatch, cut_after=10**6, cut_status=403)
    assert "끝에서 교정을 한 번 더" in r.note
    assert "검증되지 않았습니다" not in r.note


def test_unknown_response_classes_are_counted_not_dropped(monkeypatch):
    """403·429 는 '없음' 이 아니라 **막혔다**는 신호다."""
    r, _ = walled(monkeypatch, cut_after=12, cut_status=403)
    assert "뜻을 모르는 응답" in r.note
    assert "판정 못 함" in r.note


def test_end_calibration_stays_inside_the_budget(monkeypatch):
    """상한은 지켜야 한다 — 앱 한도도 같은 수를 센다."""
    _, fetch = walled(monkeypatch, cut_after=10**6, cut_status=403, budget="60")
    assert len(fetch.calls) <= 60


def test_the_report_does_not_claim_contents_were_not_fetched(monkeypatch):
    """수확하려면 본문을 받는다. '가져오지 않았다' 는 거짓이었다."""
    r, _ = bodies(monkeypatch, CHAIN, seeds=["etc/systemd/system/sesacedu-api.service"])
    assert "파일 내용은 가져오지 않았습니다" not in r.note
    assert "내용을 받습니다" in r.note              # 받는다고 적는다
    assert "어디에도 남지 않습니다" in r.note        # 어디까지 남는지도 적는다
    assert "파일 내용은 가져오지 않습니다" not in mod.META["description"]


def test_response_bodies_are_blanked_on_the_way_out(monkeypatch):
    """`_r` 에 매달린 Response 의 본문까지 비운다.

    화면은 거기서 요청기록 번호만 읽지만, '어디에도 안 남는다' 를 사실로 둔다.
    """
    r, _ = bodies(monkeypatch, CHAIN, seeds=["etc/systemd/system/sesacedu-api.service"])
    for f in r.findings:
        assert not getattr(f.response, "body", "")


def test_calibrate_returns_only_what_it_could_check(monkeypatch):
    """예산이 모자라면 관문을 다 못 본 채 돌아온다."""
    fetch = seeded({"/etc/passwd": 200})
    monkeypatch.setattr(mod, "fetch", fetch)
    w = mod._Walker(T, "123", 9, "double-full", 2)
    got = mod.calibrate(w)
    assert len(got) == 2 < len(mod.CALIBRATION)


def test_a_short_calibration_is_not_a_pass(monkeypatch):
    """관문을 **다 보지 못한** 것도 통과가 아니다 — 전에는 조용히 넘어갔다."""
    fetch = seeded({"/etc/passwd": 200})
    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(WORDS), False))
    # 관문 넷 중 둘만 보고 돌아오는 상황을 그대로 만든다(둘 다 '맞음')
    monkeypatch.setattr(mod, "calibrate",
                        lambda w: [{"path": "etc/passwd", "want": mod.READABLE,
                                    "got": mod.READABLE, "why": "", "ok": True},
                                   {"path": "etc", "want": mod.EXISTS,
                                    "got": mod.EXISTS, "why": "", "ok": True}])
    r = mod.run(T, {"mode": "seed", "wordlist": "s", "names": "", "limit": "10",
                    "kinds": "no", "depth": "9", "scheme": "double-full",
                    "lecture": "123", "hints": "", "budget": "200"})
    assert "교정 실패" in r.summary
    assert "못 봄" in str(r.rows)


def test_a_failed_depth_measurement_is_not_called_a_measurement(monkeypatch):
    """자리값 9 를 '재서 9 를 썼다' 고 적으면 측정하지 않은 값이 측정값이 된다."""
    def fetch(url, **_kw):
        return Response(url=url, status=404, headers=[], body="")

    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod.wordlists, "load", lambda *_a, **_k: (list(WORDS), False))
    r = mod.run(T, {"mode": "seed", "wordlist": "s", "names": "", "limit": "10",
                    "kinds": "no", "depth": "auto", "scheme": "double-full",
                    "lecture": "123", "hints": "", "budget": "200"})
    assert "직접 재서" not in r.note
    assert "교정 실패" in r.summary          # 못 쟀으면 교정도 실패한다


def test_a_hint_does_not_launder_into_the_modules_own_work(monkeypatch):
    """단서 본문에서 캔 경로는 퍼징의 성과가 아니다 — 수확이 출처를 세탁하지 않는다."""
    pages = {"/etc/hintfile": "EnvironmentFile=/srv/laundered/api.env\n",
             "/srv/laundered": 500, "/srv/laundered/api.env": 200}
    r, _ = bodies(monkeypatch, pages, seeds=["etc/nothing-here"],
                  hints="etc/hintfile", rounds="3")
    by = {row[0]: row[5] for row in r.rows}
    assert by.get("/etc/hintfile") == "단서(밖에서)"
    # 단서를 읽어 캐낸 것이 '수확' 으로 올라가면 안 된다
    assert "/srv/laundered" not in by


def test_skipped_wordlist_lines_are_not_double_counted(monkeypatch):
    """묶음을 둘로 갈라 돌리므로 같은 사전을 두 번 본다. 그때마다 더하면 부풀어 보인다."""
    pages = {"/srv/a": 500, "/srv/a/..": 500}
    r, _ = pipeline(monkeypatch, pages, seeds=["srv/a"],
                    names=["ok", "x/y", "..", "z/w"], budget="400")
    assert "3줄을 건너뛰었습니다" in r.note, r.note


def test_round_ceiling_is_reported_even_when_the_last_round_found_something(monkeypatch):
    """`pending` 만 보면 progress 쪽을 놓친다 — 어느 쪽이든 상한에 걸린 것은 상한이다."""
    monkeypatch.setattr(mod, "MAX_ROUNDS", 2)
    pages = {"/etc/systemd/system/x.service": "Environment=CATALINA_BASE=/srv/d\n",
             "/srv/d": 500, "/srv/d/a": 500, "/srv/d/a/b": 500,
             "/srv/d/a/b/c": 500, "/srv/d/a/b/c/d": 500}
    r, _ = bodies(monkeypatch, pages, seeds=["etc/systemd/system/x.service"],
                  words=["a", "b", "c", "d"], budget="900", rounds="3")
    assert "바퀴 상한" in r.note
    assert "스스로 멈췄습니다" not in r.note


def test_the_wordlist_counts_in_the_docs_match_the_files():
    """'159줄' 이 네 군데 적혀 있었는데 파일은 209줄이 됐다(11-06 검수)."""
    import pathlib
    root = pathlib.Path(mod.__file__).parents[3]

    def lines(name):
        text = (root / "wordlists" / name).read_text(encoding="utf-8")
        return [l.strip() for l in text.splitlines()
                if l.strip() and not l.strip().startswith("#")]

    docs = (root / "wordlists" / "README.md").read_text(encoding="utf-8")
    assert "%d개" % len(lines("fs-dirnames.txt")) in docs, len(lines("fs-dirnames.txt"))
    assert "%d개" % len(lines("fs-seeds-sesacedu.txt")) in docs
    assert "159" not in docs
