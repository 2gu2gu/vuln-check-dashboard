"""다른 도구(Burp·katana·gau 등)로 모은 URL 목록을 붙여 넣어 지점으로 등록한다. 요청은 보내지 않는다."""
import re
from urllib.parse import parse_qsl, urlsplit

from dashboard.core import Point
from modules.surface_crawl import _query_points, _split

META = {
    "id": "surface_import",
    "hidden": True,  # 표면 수집(surface_collect)이 부품으로 쓴다 — 목록에 따로 안 띄운다(11-20)
    "name": "URL 목록 가져오기",
    "category": "표면 수집",
    "kind": "passive",
    "stage": "collect",
    "attack": [{"tactic": "TA0043", "technique": "T1594", "name": "Search Victim-Owned Websites"}],
    "description": "한 줄에 하나씩 붙여 넣습니다. 'POST 주소 a=1&b=2' 처럼 쓰면 폼 본문 파라미터로 등록합니다. 범위 밖 주소는 빠집니다.",
    "params": [
        {"name": "urls", "need": "required", "label": "URL 목록", "type": "textarea", "default": "",
         "placeholder": "https://example.test/api/lectures?keyword=a\nPOST https://example.test/api/login email=a&password="},
    ],
}


PATH_VAR = re.compile(r"\{([^}/]+)\}")


def _path_points(url: str, method: str):
    """경로 틀의 {변수} 를 고를 수 있는 지점으로 만든다 → [Point].

    11-21 실측: 명세에서 뽑은 `/backend/lectures/{lid}/qna/{qnaid}` 를 URL 목록으로 넣었더니
    주소 줄만 생기고 변수가 지점이 안 돼서, IDOR 점검이 고를 것이 하나도 없었다.
    """
    return [Point(method, url, param=m.group(1), place="path", source="import")
            for m in PATH_VAR.finditer(urlsplit(url).path)]


def run(target, params):
    text = (params.get("urls") or "").strip()
    if not text:
        raise ValueError("붙여 넣을 URL 이 없습니다. 한 줄에 하나씩 넣어 주세요")
    points = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        method = parts.pop(0).upper() if parts[0].upper() in ("GET", "POST") else "GET"
        if not parts:
            continue
        url = parts[0]
        if not url.startswith(("http://", "https://")):
            url = target.url + "/" + url.lstrip("/")
        points += _query_points(url, "import", method)
        points += _path_points(url, method)
        if method == "POST" and len(parts) > 1:
            base, _ = _split(url)
            points += [Point("POST", base, param=k, place="form", sample=v, source="import")
                       for k, v in parse_qsl(parts[1], keep_blank_values=True)]
    if not points:
        raise ValueError("읽을 수 있는 주소가 없습니다. http:// 나 https:// 로 시작하거나 /courses 처럼 경로로 써 주세요")
    return points
