"""칼리에서 돌린 도구 결과를 붙여 넣으면 표면·결과로 옮겨 준다.

대시보드는 바깥 도구를 대신 실행하지 않는다 — 그러면 범위 검사가 그 도구가 보내는 것까지
닿지 못한다. 그래서 칼리에서 사람이 돌리고, 결과만 여기로 가져온다.

받는 모양
  ffuf      `ffuf -w list -u https://.../FUZZ -of json -o out.json` 의 json
  gobuster  `gobuster dir -u ... -w list` 의 화면 출력 또는 `-o out.txt`
  nuclei    `nuclei -u ... -jsonl` 의 한 줄 json 여러 줄
  URL 목록  그냥 주소만 한 줄에 하나 (katana·gau·hakrawler 등)
어느 것인지 고르지 않아도 모양을 보고 알아서 읽는다. 범위 밖 주소는 빠진다.
"""
import json
import re

from dashboard.core import Finding, Point, ToolResult

META = {
    "id": "import_tool_output",
    "name": "칼리 도구 결과 가져오기",
    "category": "표면 수집",
    "kind": "passive",
    "stage": "tool",
    "severity": "medium",
    "attack": [{"tactic": "TA0043", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning"}],
    "description": "ffuf·gobuster·nuclei 결과나 URL 목록을 붙여 넣으면 표면 지점으로 옮깁니다. nuclei 결과는 결과 탭에도 올립니다. 요청은 보내지 않습니다.",
    "needs": [
        {"kind": "tool", "name": "ffuf · gobuster · nuclei",
         "why": "대시보드가 바깥 도구를 대신 실행하지 않습니다 — 그러면 범위 검사가 그 도구가 보내는 것까지 닿지 못합니다",
         "how": "칼리에서 직접 돌리고(ffuf 는 -of json, nuclei 는 -jsonl) 나온 결과를 붙여 넣습니다"},
    ],
    "params": [
        {"name": "output", "label": "도구 결과 붙여 넣기", "type": "textarea", "default": "",
         "placeholder": '{"results":[{"url":"https://example.test/admin","status":200,"length":1234}]}\n'
                        '또는  /admin  (Status: 200) [Size: 1234]\n'
                        '또는  https://example.test/api/v1/users'},
    ],
}

NUCLEI_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
              "unknown": "info"}
GOBUSTER = re.compile(r"^(/\S*)\s+\(Status:\s*(\d{3})\)")
URL_LINE = re.compile(r"https?://\S+")
MAX_LINES = 3000


def _point(url, source):
    from modules.surface_crawl import _query_points
    return _query_points(url, source)


def run(target, params):
    text = (params.get("output") or "").strip()
    if not text:
        raise ValueError("칼리에서 받은 결과를 붙여 넣어 주세요")
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(f"한 번에 {MAX_LINES}줄까지 읽습니다 (지금 {len(lines)}줄)")

    points, findings, kinds = [], [], set()

    # ① ffuf — 통째로 json
    try:
        blob = json.loads(text)
        if isinstance(blob, dict) and isinstance(blob.get("results"), list):
            kinds.add("ffuf")
            for item in blob["results"]:
                if item.get("url"):
                    points += _point(item["url"], "ffuf")
    except ValueError:
        blob = None

    if not kinds:
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # ② nuclei — 한 줄에 json 하나
            if line.startswith("{"):
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                url = item.get("matched-at") or item.get("host") or ""
                info = item.get("info") or {}
                if not url:
                    continue
                kinds.add("nuclei")
                points += _point(url, "nuclei")
                findings.append(Finding(
                    title=f"[nuclei] {info.get('name') or item.get('template-id') or '이름 없음'}",
                    severity=NUCLEI_SEV.get((info.get("severity") or "info").lower(), "info"),
                    location=url,
                    evidence=f"template: {item.get('template-id', '-')}\n"
                             f"matched-at: {url}\n"
                             f"{(item.get('matcher-name') or '')}".strip(),
                    recommendation=(info.get("description") or "nuclei 템플릿 설명을 확인하고 해당되는지 직접 재현해 보세요.").strip()))
                continue

            # ③ gobuster — /admin (Status: 200)
            m = GOBUSTER.match(line)
            if m:
                kinds.add("gobuster")
                points += _point(target.url.rstrip("/") + m.group(1), "gobuster")
                continue

            # ④ 그냥 URL 목록
            m = URL_LINE.search(line)
            if m:
                kinds.add("url")
                points += _point(m.group(0), "import")

    if not points and not findings:
        raise ValueError("읽을 수 있는 줄이 없습니다. ffuf json · gobuster 출력 · nuclei jsonl · URL 목록을 넣어 주세요")

    return ToolResult(
        summary=f"{', '.join(sorted(kinds)) or '알 수 없음'} 에서 지점 {len(points)}개"
                + (f" · 결과 {len(findings)}건" if findings else ""),
        columns=["메서드", "주소", "파라미터"],
        rows=[[p.method, p.url, p.param or "—"] for p in points[:50]],
        findings=findings,
        note=("위에 보이는 것은 앞 50개입니다. 표면 탭에 모두 들어갑니다. "
              "범위 밖 주소는 저장할 때 빠집니다. 요청은 보내지 않았습니다."),
        points=points)
