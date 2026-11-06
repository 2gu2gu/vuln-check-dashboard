"""사전에 적힌 경로를 하나씩 눌러 보며 링크에 없는 엔드포인트를 찾는다(gobuster·ffuf 가 하는 일).

페이지를 따라가는 수집은 **링크로 이어진 곳**만 찾는다. 관리 화면·백업 파일처럼
아무 데서도 가리키지 않는 경로는 이렇게 이름을 찍어 봐야 나온다.

'없는 경로에도 200 을 주는' 서버(SPA 등)에 속지 않도록, 먼저 아무 말이나 지어낸 경로를
두 번 넣어 보고 그 응답 모양을 기준으로 삼는다. 기준과 같으면 없는 것으로 본다.
"""
import uuid

from dashboard.core import Point, fetch, join

META = {
    "id": "content_discovery",
    "name": "숨은 경로 찾기",
    "category": "표면 수집",
    "kind": "active",
    "stage": "collect",
    "attack": [{"tactic": "TA0043", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning"}],
    "description": "사전의 경로를 하나씩 요청해 링크에 없는 엔드포인트를 찾습니다. 찾은 경로는 표면 탭에 등록됩니다.",
    "needs": [
        {"kind": "env", "name": "DASH_WORDLISTS", "required": False,
         "why": "저장소에 든 씨앗 사전만으로는 찾는 범위가 좁습니다. SecLists 를 붙이면 고르는 칸에 함께 뜹니다",
         "how": "SecLists 를 받아 대시보드를 띄우기 전에 DASH_WORDLISTS 에 그 폴더를 넣습니다 (wordlists/README.md)"},
    ],
    "params": [
        {"name": "wordlist", "need": "required", "label": "사전", "type": "wordlist", "purpose": "path", "default": "web-common.txt"},
        {"name": "base", "need": "optional", "label": "기준 경로", "default": "/",
         "help": "이 아래에서 찾습니다. 예: /  또는 /backend"},
        {"name": "limit", "need": "optional", "label": "몇 개까지", "type": "int", "default": "150",
         "help": "사전 앞에서부터 이만큼만 봅니다. 하나에 요청 한 번입니다."},
    ],
}

SKIP_STATUS = {404, 410}
SIMILAR = 0.05   # 기준 응답과 길이 차이가 이 비율 안이면 같은 페이지로 본다


def _baseline(target, base):
    """없는 경로에 서버가 어떻게 답하는지 두 번 재 둔다."""
    out = []
    for _ in range(2):
        r = fetch(join(target.url, base.strip("/") + "/vcd" + uuid.uuid4().hex[:10]))
        out.append((r.status, len(r.body)))
    return out


def _looks_missing(status, size, baseline):
    for b_status, b_size in baseline:
        if status != b_status:
            continue
        if b_size == 0 and size == 0:
            return True
        if b_size and abs(size - b_size) <= b_size * SIMILAR:
            return True
    return False


def run(target, params):
    from dashboard.wordlists import load
    words, _ = load(params.get("wordlist", ""), limit=int(params.get("limit") or 150))
    base = params.get("base", "/")
    if not words:
        raise ValueError("사전이 비어 있습니다")

    baseline = _baseline(target, base)
    points = []
    for word in words:
        path = (base.strip("/") + "/" + word.strip().lstrip("/")).strip("/")
        r = fetch(join(target.url, path))
        if r.status in SKIP_STATUS or _looks_missing(r.status, len(r.body), baseline):
            continue
        points.append(Point("GET", join(target.url, path), place="path", source="wordlist"))
    return points
