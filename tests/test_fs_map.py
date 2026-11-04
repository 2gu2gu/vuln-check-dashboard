# -*- coding: utf-8 -*-
"""칼리 fsmap 결과 가져오기 모듈."""
import json

import pytest

from dashboard.core import Target, ToolResult
from projects.sesacedu.modules import material_fs_map

T = Target(1, "t", "https://sesacedu.store")

SAMPLE = {
    "tool": "fsmap",
    "meta": {"base_url": "https://sesacedu.store", "endpoint": "/backend/lectures/123/material/download",
             "depth": 9, "scheme": "double-full", "window": "2026-11-04 23:10:00 ~ 23:12:30"},
    "stats": {"요청": 142},
    "nodes": [
        {"path": "/etc", "class": "exists", "status": 500, "size": 0, "kind": "dir",
         "is_dir": True, "note": "설정 루트", "severity": "info"},
        {"path": "/etc/passwd", "class": "readable", "status": 200, "size": 1990,
         "kind": None, "is_dir": None, "note": "계정 목록", "severity": "medium"},
        {"path": "/etc/shadow", "class": "exists", "status": 500, "size": 0,
         "kind": "opaque", "is_dir": None, "note": "권한 정상", "severity": "critical"},
        {"path": "/opt/tomcat/conf/tomcat-users.xml", "class": "readable", "status": 200,
         "size": 2048, "kind": None, "is_dir": None, "note": "관리 계정", "severity": "critical"},
        {"path": "/srv", "class": "exists", "status": 500, "size": 0, "kind": "dir",
         "is_dir": True, "probed_children": 300, "child_hits": 0, "blocked": True,
         "note": "", "severity": "info"},
    ],
    "stopped": "",
}


def run(params=None):
    body = dict({"fsmap": json.dumps(SAMPLE, ensure_ascii=False), "min_severity": "high"},
                **(params or {}))
    return material_fs_map.run(T, body)


def test_reads_fsmap_and_counts_states():
    r = run()
    assert isinstance(r, ToolResult)
    assert "존재 5" in r.summary
    assert "읽힘 2" in r.summary
    assert "디렉터리 2" in r.summary      # /etc, /srv
    assert "못 들어감 1" in r.summary     # /etc/shadow
    assert "막힌 가지 1" in r.summary     # /srv


def test_draws_a_tree_with_intermediate_paths():
    text = run().text
    assert text.splitlines()[0].strip() == "/"
    assert "etc/" in text and "passwd" in text
    # /opt 와 /opt/tomcat 은 때리지 않았으므로 중간 경로로 그려진다
    assert "(중간 경로)" in text
    assert "tomcat-users.xml" in text


def test_tree_marks_unreadable_separately_from_readable():
    text = run().text
    assert "[200 · 1.9KB]" in text
    assert "못 들어감: 파일/디렉터리 구분 불가" in text


def test_does_not_claim_opaque_is_a_file():
    """500 + '/..' 404 는 못 읽는 파일일 수도, 못 들어가는 디렉터리일 수도 있다."""
    r = run()
    assert "권한 없음]" not in r.text
    shadow = [row for row in r.rows if row[0] == "/etc/shadow"][0]
    assert shadow[3] == "못 들어감"      # '파일' 이라고 적지 않는다


def test_does_not_claim_a_blocked_directory_is_empty():
    r = run()
    assert "안쪽 전부 404" in r.text
    srv = [row for row in r.rows if row[0] == "/srv"][0]
    assert srv[5] == "있음 · 안쪽 전부 404"
    assert "비었거나 탐색 권한 없음" in r.text


def test_note_warns_that_404_is_not_absence():
    note = run().note
    assert "404" in note and "탐색 권한" in note


def test_legend_warns_that_404_is_not_absence():
    assert "탐색 권한 없음" in run().text


def test_old_format_is_dir_false_is_not_trusted_as_file():
    """예전 fsmap 은 is_dir=False 로 '파일'이라 단정했다. 그 값을 믿지 않는다."""
    sample = {"nodes": [{"path": "/root", "class": "exists", "status": 500, "size": 0,
                         "is_dir": False, "severity": "high"}]}
    r = material_fs_map.run(T, {"fsmap": json.dumps(sample), "min_severity": "high"})
    assert "못 들어감 0" in r.summary       # opaque 로도 세지 않는다
    assert "종류 미판별" in r.text          # 모른다고 적는다


def test_findings_summary_plus_sensitive_files():
    r = run()
    titles = [f.title for f in r.findings]
    assert any("구조 확인" in t for t in titles)
    assert any("tomcat-users.xml" in t for t in titles)
    # 민감도 medium 인 /etc/passwd 는 기본(높음 이상)에서 개별 결과로 올리지 않는다
    assert not any("etc/passwd" in t for t in titles)


def test_min_severity_widens_the_findings():
    titles = [f.title for f in run({"min_severity": "medium"}).findings]
    assert any("etc/passwd" in t for t in titles)


def test_evidence_has_no_file_contents():
    """fsmap 결과에는 내용이 없다. 근거에도 경로·크기·코드만 들어가야 한다."""
    for f in run().findings:
        assert "root:x:" not in f.evidence
        assert "password" not in f.evidence.lower()


def test_only_readable_rows_get_a_drill():
    r = run()
    for row, drill in zip(r.rows, r.drills):
        if row[5] == "읽힘":
            assert drill and "내용 보기" in drill
        else:
            assert drill is None


def test_drill_strips_leading_slash_for_the_traversal_tool():
    """경로 조작 도구의 paths 는 맨 앞 / 를 빼고 받는다."""
    r = run()
    paths = [d["내용 보기"]["paths"] for d in r.drills if d]
    assert paths and all(not p.startswith("/") for p in paths)


def test_sends_no_requests():
    assert not hasattr(material_fs_map, "fetch")


def test_warns_when_kali_side_stopped_early():
    sample = dict(SAMPLE, stopped="401 — 토큰 만료")
    r = material_fs_map.run(T, {"fsmap": json.dumps(sample, ensure_ascii=False),
                                "min_severity": "high"})
    assert "완전하지 않" in r.note


@pytest.mark.parametrize("bad, msg", [
    ("", "붙여 넣어"),
    ("not json", "JSON"),
    ('{"hello":1}', "nodes"),
    ('{"nodes":[]}', "비어"),
])
def test_rejects_bad_input(bad, msg):
    with pytest.raises(ValueError) as exc:
        material_fs_map.run(T, {"fsmap": bad, "min_severity": "high"})
    assert msg in str(exc.value)


def test_limits_node_count():
    big = {"nodes": [{"path": "/x/%d" % i, "class": "readable", "status": 200, "size": 1}
                     for i in range(material_fs_map.MAX_NODES + 1)]}
    with pytest.raises(ValueError) as exc:
        material_fs_map.run(T, {"fsmap": json.dumps(big), "min_severity": "high"})
    assert "까지 읽습니다" in str(exc.value)
