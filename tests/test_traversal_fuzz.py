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
    body = dict({"mode": "seed", "wordlist": "", "limit": "10",
                 "kinds": "yes", "depth": "9", "scheme": "double-full",
                 "lecture": "123"}, **params)
    monkeypatch.setattr(mod.wordlists, "load",
                        lambda *_a, **_k: (params.pop("_words", None) or WORDS, False))
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
