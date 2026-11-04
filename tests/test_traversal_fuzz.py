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
        status = pages.get(path, default)
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
    assert not any(p.endswith("/..") for p in fetch.calls)
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
    many = ["etc/p%d" % i for i in range(mod.MAX_REQUESTS * 2)]
    r, fetch = run(monkeypatch, {}, kinds="no", limit="99999", _words=many)
    assert len(fetch.calls) <= mod.MAX_REQUESTS
    assert "까지 보냅니다" in r.note


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


def bodies(monkeypatch, pages, seeds, **params):
    """경로별로 본문까지 돌려주는 가짜 서버."""
    calls = []

    def fetch(url, **_kw):
        payload = parse_qs(urlsplit(url).query).get("file", [""])[0]
        path = "/" + unquote(unquote(payload)).replace("../", "").lstrip("/")
        calls.append(path)
        base = path[:-3] if path.endswith("/..") else path
        if base in pages and isinstance(pages[base], str):
            return Response(url=url, status=200, headers=[], body=pages[base])
        if base in pages:
            return Response(url=url, status=pages[base], headers=[], body="")
        return Response(url=url, status=404, headers=[], body="")

    fetch.calls = calls
    monkeypatch.setattr(mod, "fetch", fetch)
    turn = {"n": 0}

    def load(*_a, **_k):
        turn["n"] += 1
        return (list(seeds) if turn["n"] == 1 else ["zzz"]), False

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
