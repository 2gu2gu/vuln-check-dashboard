"""실행 결과 본문(경로 조작 퍼징의 트리 등)을 파일로 남긴다. DB 는 쓰지 않는다.

왜 파일인가 — 트리는 **그 자체로 읽는 산출물**이다. 보고서에 붙이고, 팀에 넘기고, 다음
실행과 비교한다. DB 안에만 두면 대시보드를 받아 쓰는 사람이 sqlite 를 열어야 꺼낼 수 있다.

폴더가 색인이다.

    instance/runs/<대상번호>-<대상이름>/<모듈>/<실행번호>.txt

대상·모듈이 경로에 들어 있어 "이 대상의 이 모듈, 마지막 실행" 은 폴더만 보면 된다.
실행번호가 파일명이라 정렬도 그대로다. 표시할 자리는 `DASH_RUNS_DIR` 로 옮길 수 있다.
"""
import re
from pathlib import Path

SAFE = re.compile(r"[^0-9A-Za-z가-힣._-]+")


def _slug(s, n=40):
    return SAFE.sub("-", str(s or "")).strip("-")[:n] or "x"


def base_dir(app):
    return Path(app.config["RUNS_DIR"])


def _folder(app, target, module_id):
    return base_dir(app) / f"{target['id']}-{_slug(target['name'], 24)}" / _slug(module_id)


def save(app, run_id, target, mod, text, summary=""):
    """파일로 적고 경로(Path)를 돌려준다.

    파일만 떼어 가도 무엇을, 언제, 어디에 대고 돌린 것인지 알 수 있게 머리말을 붙인다.
    """
    from .core import fmt_kst, now_iso

    path = _folder(app, target, mod.id) / f"{run_id:04d}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    head = (f"# {mod.name}\n"
            f"# 대상: {target['name']} — {target['url']}\n"
            f"# 실행 #{run_id} · {fmt_kst(now_iso())}\n")
    if summary:
        head += f"# {summary}\n"
    path.write_text(head + "\n" + text, encoding="utf-8")
    return path


def find(app, target, module_id, run_id=None):
    """그 실행의 파일, `run_id` 가 없으면 이 대상·이 모듈의 **마지막** 실행 파일."""
    folder = _folder(app, target, module_id)
    if run_id:
        path = folder / f"{run_id:04d}.txt"
        return path if path.exists() else None
    try:
        files = sorted(folder.glob("[0-9]*.txt"))
    except OSError:
        return None
    return files[-1] if files else None


def run_ids(app):
    """파일이 남아 있는 실행 번호. 목록 화면에서 '내용 보기' 를 붙일지 가린다."""
    out = set()
    for p in base_dir(app).glob("*/*/[0-9]*.txt"):
        try:
            out.add(int(p.stem))
        except ValueError:
            pass
    return out


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None
