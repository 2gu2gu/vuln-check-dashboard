# -*- coding: utf-8 -*-
"""연습용 대상(demo_target.py) — 실서버와 **응답 코드가 같은지**를 본다.

구조 그리기 모듈은 200·500·404 를 오라클로 써서 트리를 그린다. 연습 서버가 디렉터리에
404 를 주면 모듈은 여기서 아무 구조도 못 그리고, 그러면 실서버 전에 시험해 볼 곳이 없다.
그래서 이 코드 세 줄이 트리를 그릴 수 있는지를 결정한다.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import demo_target as dt  # noqa: E402
from dashboard.payloads import traversal  # noqa: E402

BEARER = {"Authorization": "Bearer demo-not-real"}
DOWNLOAD = "/backend/lectures/123/material/download?file="


@pytest.fixture
def web():
    dt.app.config["TESTING"] = True
    return dt.app.test_client()


def get(web, rel, headers=BEARER, depth=9):
    """최상위에서 시작하는 경로를 때린다.

    페이로드는 모듈이 쓰는 그 함수로 만든다 — 인코딩이 바뀌면 이 시험도 같이 깨져야 한다.
    """
    return web.get(DOWNLOAD + traversal(rel, depth, "double-full"), headers=headers)


# ── 오라클 ────────────────────────────────────────────────────
def test_a_file_comes_back_200(web):
    r = get(web, "etc/passwd")
    assert r.status_code == 200 and b"root:x:0:0" in r.data


def test_a_directory_comes_back_500(web):
    """실서버와 같아야 한다 — 있는데 파일로 못 보내면 500 이다.

    404 를 주면 모듈이 디렉터리를 하나도 못 찾아 트리가 빈다.
    """
    for d in ("etc", "etc/nginx", "srv/sesacedu", "opt/java/jdk-11.0.24+8"):
        assert get(web, d).status_code == 500, d


def test_a_missing_path_comes_back_404(web):
    assert get(web, "etc/nope-xyz").status_code == 404


def test_outside_the_sandbox_is_404(web):
    """모래상자 밖은 없는 것으로 둔다 — 연습 서버가 진짜 디스크를 읽으면 안 된다."""
    assert get(web, "Windows/win.ini", depth=40).status_code == 404


def test_no_token_is_401(web):
    assert get(web, "etc/passwd", headers={}).status_code == 401


# ── 수확 고리가 돌아갈 재료 ───────────────────────────────────
def test_the_unit_file_spells_out_absolute_paths(web):
    """읽힌 설정 파일이 다음 경로를 알려 준다 — 수확이 여기서 시작된다."""
    body = get(web, "etc/systemd/system/sesacedu-api.service").data.decode()
    for path in ("/srv/sesacedu/app", "/srv/sesacedu/config/api.env", "/opt/java/jdk-11.0.24+8"):
        assert path in body, path


def test_harvest_reaches_a_name_no_wordlist_has(web):
    """버전이 박힌 이름은 어떤 사전에도 없다. 수확으로만 닿는다."""
    root = Path(__file__).resolve().parents[1] / "wordlists"
    words = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in root.glob("*.txt"))
    assert "jdk-11.0.24+8" not in words          # 사전에는 없고
    assert get(web, "opt/java/jdk-11.0.24+8").status_code == 500   # 서버에는 있다
