"""사전(wordlist) 찾아 읽기.

저장소의 `wordlists/` 와, 환경변수 `DASH_WORDLISTS` 가 가리키는 폴더(SecLists 등)를 함께 본다.
`.txt` 만, 하위 한 단계까지. 한 번에 읽는 줄 수에는 한도를 둔다 — 큰 목록을 통째로 쏘지 않기 위해서.
"""
import os
from pathlib import Path

BUNDLED = Path(__file__).resolve().parent.parent / "wordlists"
MAX_LINES = 5000          # 파일 하나에서 읽어 들이는 최대 줄 수
MAX_FILES = 300           # 목록에 보여 주는 최대 파일 수


def roots():
    """볼 폴더들. 앞이 저장소 기본, 뒤가 사용자가 가리킨 곳."""
    out = [BUNDLED] if BUNDLED.is_dir() else []
    for part in os.environ.get("DASH_WORDLISTS", "").replace(";", os.pathsep).split(os.pathsep):
        path = Path(part.strip())
        if part.strip() and path.is_dir():
            out.append(path)
    return out


def available():
    """[{value: 고른 값, label: 보일 이름}] — 화면의 고르는 칸에 그대로 쓴다."""
    found, seen = [], set()
    for root in roots():
        tag = "기본" if root == BUNDLED else root.name
        for path in sorted(list(root.glob("*.txt")) + list(root.glob("*/*.txt"))):
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            rel = path.relative_to(root).as_posix()
            found.append({"value": f"{root}|{rel}", "label": f"{tag} / {rel}"})
            if len(found) >= MAX_FILES:
                return found
    return found


def load(choice: str, limit: int = MAX_LINES):
    """고른 사전을 읽어 줄 목록으로. '#' 로 시작하는 줄과 빈 줄은 건너뛴다."""
    root, _, rel = (choice or "").partition("|")
    if not rel:
        raise ValueError("사전을 골라 주세요")
    base = Path(root).resolve()
    path = (base / rel).resolve()
    if base not in path.parents and path != base:      # 폴더 밖으로 나가지 못하게
        raise ValueError(f"사전 경로가 올바르지 않습니다: {rel}")
    if not any(path == p.resolve() or p.resolve() in path.parents for p in roots()):
        raise ValueError(f"등록되지 않은 사전 폴더입니다: {base}")
    if not path.is_file():
        raise ValueError(f"사전 파일이 없습니다: {rel}")

    lines, cut = [], False
    with path.open(encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n\r")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            lines.append(line)
            if len(lines) >= limit:
                cut = True
                break
    return lines, cut
