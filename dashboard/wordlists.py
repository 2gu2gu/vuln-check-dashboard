"""사전(wordlist) 찾아 읽기.

저장소의 `wordlists/` 와, 환경변수 `DASH_WORDLISTS` 가 가리키는 폴더(SecLists 등)를 함께 본다.

SecLists 를 붙이면 파일이 수천 개가 된다. 그래서 세 가지를 한다.
  1. 용도로 가른다 — 경로 찾기 모듈에 비밀번호 목록이 뜨면 소음이다.
     맞는 것을 위에 두되 나머지도 아래에 남긴다(아는 사람이 다른 걸 쓰려 할 때 막지 않는다).
  2. 크기를 라벨에 적는다 — 수만 줄짜리를 모르고 고르면 요청 상한에 걸려 중간에 멈춘다.
  3. 다 못 보여 주면 **잘렸다고 말한다**. 조용히 자르면 왜 안 보이는지 알 수 없다.
"""
import os
from pathlib import Path

BUNDLED = Path(__file__).resolve().parent.parent / "wordlists"
MAX_LINES = 5000          # 파일 하나에서 읽어 들이는 최대 줄 수
MAX_FILES = 3000          # 목록에 보여 주는 최대 파일 수(넘으면 잘렸다고 알린다)
MAX_DEPTH = 3             # 폴더를 몇 단계까지 내려가 볼지. SecLists 는 Discovery/Web-Content/x.txt 로 2단계다

PURPOSE_LABEL = {
    "path": "경로",
    "payload": "입력값",
    "password": "비밀번호",
    "username": "계정 이름",
    "param": "파라미터 이름",
    "subdomain": "하위 도메인",
    "other": "그 밖",
}

# SecLists 최상위 폴더가 이미 용도별로 갈려 있다 — 그대로 쓴다.
# 긴 경로를 먼저 보고, 없으면 짧은 쪽을 본다.
BY_FOLDER = {
    "discovery/web-content": "path",
    "discovery/file-system": "path",
    "discovery/variables": "param",
    "discovery/dns": "subdomain",
    "discovery/infrastructure": "other",
    "discovery/snmp": "other",
    "discovery/mainframe": "other",
    "fuzzing": "payload",
    "payloads": "payload",
    "passwords": "password",
    "usernames": "username",
    "pattern-matching": "other",
    "web-shells": "other",
    "miscellaneous": "other",
    "ai": "other",
}

# 폴더보다 **먼저** 보는 이름. SecLists 의 `Fuzzing/LFI/` 에는 두 가지가 섞여 있다.
#   LFI-gracefulsecurity-linux.txt  →  `/etc/ssh/ssh_host_rsa_key` 처럼 **절대경로 목록**
#   LFI-Jhaddix.txt                 →  `../` 와 `%00` 이 든 **페이로드**
# 폴더(`fuzzing` → 입력값)만 보면 앞쪽이 틀리게 갈려 경로 찾기 모듈의 '이 모듈용' 에서 밀려난다.
PATH_NAMES = ("gracefulsecurity", "etc-files", "pathtotest")

# 폴더로 못 가리면 파일 이름을 본다. 위에서부터 먼저 맞는 것.
BY_NAME = [
    ("payload", ("payload", "fuzz", "xss", "sqli", "sql-", "lfi", "rfi", "traversal", "xxe", "ssti", "injection")),
    ("password", ("password", "passwd", "credential", "rockyou")),
    ("username", ("username", "user-", "login-", "account")),
    ("param", ("param", "variable")),
    ("subdomain", ("subdomain", "dns", "vhost")),
    ("path", ("web", "dir", "path", "raft", "common", "backup", "config", "file", "endpoint", "api")),
]


def classify(rel: str) -> str:
    """상대 경로 하나를 용도로 가른다."""
    low = rel.replace("\\", "/").lower()
    parts = low.split("/")
    if any(w in parts[-1] for w in PATH_NAMES):  # 폴더보다 이름이 확실한 것 먼저
        return "path"
    for depth in (2, 1):                         # discovery/web-content → discovery 순으로
        if len(parts) > depth:
            hit = BY_FOLDER.get("/".join(parts[:depth]))
            if hit:
                return hit
    name = parts[-1]
    for purpose, words in BY_NAME:
        if any(w in name for w in words):
            return purpose
    return "other"


def size_label(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n // 1024} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def roots():
    """볼 폴더들. 앞이 저장소 기본, 뒤가 사용자가 가리킨 곳."""
    out = [BUNDLED] if BUNDLED.is_dir() else []
    for part in os.environ.get("DASH_WORDLISTS", "").replace(";", os.pathsep).split(os.pathsep):
        path = Path(part.strip())
        if part.strip() and path.is_dir():
            out.append(path)
    return out


def _walk(root: Path):
    """root 아래 .txt 를 MAX_DEPTH 단계까지. 숨은 폴더(.git 등)는 건너뛴다."""
    for depth in range(MAX_DEPTH + 1):
        pattern = "/".join(["*"] * depth + ["*.txt"]) if depth else "*.txt"
        for path in sorted(root.glob(pattern)):
            if any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            yield path


def available(purpose: str = "") -> dict:
    """고르는 칸에 쓸 목록.

    {"items": [...], "total": 찾은 전체 수, "cut": 잘렸는지}
    items 는 요청한 용도에 맞는 것이 앞에 오고, 묶음(group)별로 정렬돼 있다.
    """
    items, seen, total = [], set(), 0
    for root in roots():
        bundled = root == BUNDLED
        for path in _walk(root):
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            total += 1
            if len(items) >= MAX_FILES:
                continue
            rel = path.relative_to(root).as_posix()
            what = "path" if bundled and classify(rel) == "other" else classify(rel)
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            items.append({
                "value": f"{root}|{rel}",
                "name": rel,
                "purpose": what,
                "group": ("기본" if bundled else root.name) + f" · {PURPOSE_LABEL[what]}",
                "size": size,
                "size_label": size_label(size),
                "match": (not purpose) or what == purpose,
                # 예전 화면이 쓰던 이름 — 한 줄로 보여 줄 때 쓴다
                "label": ("기본" if bundled else root.name) + " / " + rel,
            })

    items.sort(key=lambda o: (not o["match"], not o["group"].startswith("기본"), o["group"], o["name"]))

    # 묶음은 '맞는 것 먼저' 순서를 그대로 지켜야 한다.
    # Jinja 의 groupby 를 쓰면 글자순으로 다시 늘어서서 그 순서가 사라진다.
    groups, index = [], {}
    for o in items:
        if o["group"] not in index:
            index[o["group"]] = len(groups)
            label = o["group"] + ("  — 이 모듈용" if purpose and o["match"] else "")
            groups.append({"label": label, "match": o["match"], "items": []})
        groups[index[o["group"]]]["items"].append(o)

    return {"items": items, "groups": groups, "total": total, "cut": total > len(items)}


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
