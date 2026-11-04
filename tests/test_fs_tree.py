# -*- coding: utf-8 -*-
"""디렉터리 구조를 글자 트리로 그리기.

'칼리 fsmap 결과 가져오기' 모듈을 없애면서(대시보드가 직접 퍼징해 같은 지도를 그린다)
그리는 일만 fs_tree 로 남겼다. **단정하지 않는지**를 주로 본다 —
404 를 '없음'으로, 가리지 못한 500 을 '파일'로 적는 순간 보고서가 틀린다.
"""
import pytest

from projects.sesacedu.fs_tree import DIR, OPAQUE, _size, _tree


def node(path, klass="readable", status=200, **kw):
    return dict({"path": path, "class": klass, "status": status, "severity": "info"}, **kw)


@pytest.mark.parametrize("n, want", [(0, "0B"), (512, "512B"), (2048, "2.0KB"), (3145728, "3.0MB")])
def test_size(n, want):
    assert _size(n) == want


def test_nests_by_path():
    txt = _tree([node("/srv/app/api.env"), node("/srv/app", "exists", 500, kind=DIR)])
    assert "srv/" in txt and "app/" in txt and "api.env" in txt


def test_a_readable_file_shows_its_size():
    assert "[200 · 12B]" in _tree([node("/a/b.txt", size=12)])


def test_a_directory_ends_with_a_slash():
    assert "b/" in _tree([node("/a/b", "exists", 500, kind=DIR)])


def test_does_not_claim_opaque_is_a_file():
    """못 읽는 파일과 탐색 권한 없는 디렉터리는 같은 404 를 준다 — 가릴 수 없다."""
    txt = _tree([node("/a/b", "exists", 500, kind=OPAQUE)])
    assert "파일/디렉터리 구분 불가" in txt


def test_unjudged_node_says_so():
    assert "종류 미판별" in _tree([node("/a/b", "exists", 500)])


def test_middle_paths_are_marked():
    assert "(중간 경로)" in _tree([node("/a/b/c.txt")])


def test_legend_warns_that_404_is_not_absence():
    txt = _tree([node("/a.txt")])
    assert "404 는 그리지 않는다" in txt and "탐색 권한 없음" in txt


def test_blocked_directory_is_not_called_empty():
    txt = _tree([node("/srv", "exists", 500, kind=DIR, blocked=True)])
    assert "사전 미포함" in txt and "탐색 권한 없음" in txt
    assert "비어 있" not in txt


def test_severity_marks():
    assert "!!" in _tree([node("/a", severity="critical")])
    assert "! " in _tree([node("/a", severity="high")])


def test_old_is_dir_false_is_not_trusted():
    """예전 형식의 is_dir=False 는 '파일'이라는 틀린 단정이었다."""
    assert "종류 미판별" in _tree([node("/a/b", "exists", 500, is_dir=False)])
