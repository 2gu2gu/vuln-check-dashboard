"""표면 수집 — 하나로 묶은 것(11-20 사용자 결정).

수집 도구가 여섯 개로 흩어져 있어 무엇을 어떤 순서로 돌려야 할지 몰랐다. 이 모듈 하나가 정한 순서로
돈다. 예전 수집 모듈들은 모듈 목록에서 숨기고(hidden) 부품으로 쓴다.

  1. 붙여 넣기(있으면)   URL 목록 · HAR · ffuf/gobuster/nuclei 결과 — 형식을 알아서 가린다. 요청은 보내지 않는다.
                         로그인해야 보이는 API(관리자 웹 등)는 브라우저로 둘러본 HAR 이 가장 정확하다.
  2. 자동 수집           페이지·폼·robots·sitemap·API 명세·JS 번들을 읽고, 모은 경로가 정말 있는지 확인한다(surface_discover).
  3. 숨은 경로 찾기(고르면) 사전의 경로를 하나씩 요청해 링크에 없는 주소를 찾는다(content_discovery).
"""
from modules import content_discovery, har_import, import_tool_output, surface_discover, surface_import

META = {
    "id": "surface_collect",
    "name": "표면 수집",
    "category": "표면 수집",
    "kind": "active",
    "stage": "collect",
    "attack": [{"tactic": "TA0043", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning"},
               {"tactic": "TA0043", "technique": "T1594", "name": "Search Victim-Owned Websites"}],
    "description": "**이것 하나만 돌리면 됩니다.** ① 붙여 넣은 것(URL 목록·HAR·칼리 도구 결과)을 먼저 올리고 "
                   "② 페이지·robots·API 명세·JS 번들을 읽어 자동으로 모은 뒤 경로가 정말 있는지 확인하고 "
                   "③ 고르면 사전으로 숨은 경로까지 찾습니다. 로그인해야 보이는 API 는 브라우저로 둘러본 **HAR** 을 붙여 넣는 게 가장 정확합니다.",
    "params": [
        {"name": "mode", "need": "required", "label": "어디까지 할지", "type": "select", "default": "auto",
         "options": [{"value": "auto", "label": "② 자동 수집까지 (처음엔 이것)"},
                     {"value": "deep", "label": "② 자동 수집 + ③ 숨은 경로 찾기"},
                     {"value": "paste", "label": "① 붙여 넣은 것만 (요청 안 보냄)"}]},
        {"name": "paste", "need": "optional", "label": "① 붙여 넣기", "type": "textarea", "default": "",
         "placeholder": "https://sesacedu.store/backend/lectures?keyword=a\nPOST /login email=a&pw=b\n— 또는 HAR(JSON)·ffuf·gobuster·nuclei 결과",
         "help": "형식은 알아서 가립니다. 요청을 보내지 않습니다."},
        {"name": "wordlist", "need": "conditional", "when": "③ 숨은 경로 찾기를 고를 때만", "label": "③ 사전",
         "type": "wordlist", "purpose": "path", "default": "web-common.txt"},
        {"name": "max_pages", "need": "optional", "label": "② 읽을 페이지 수", "type": "int", "default": "30"},
    ],
}


def _defaults(meta):
    return {p["name"]: p.get("default", "") for p in meta.get("params", [])}


def paste_kind(text):
    """붙여 넣은 글이 무슨 형식인지."""
    t = text.lstrip()
    if t.startswith("{") and '"log"' in t and '"entries"' in t:
        return "har"
    if import_tool_output.GOBUSTER.search(t) or '"results"' in t or t.startswith("[") or '"template-id"' in t \
            or "[nuclei" in t.lower():
        return "tool"
    return "urls"


def from_paste(target, text):
    kind = paste_kind(text)
    if kind == "har":
        return har_import.run(target, {"har": text}), "HAR"
    if kind == "tool":
        try:
            return list(import_tool_output.run(target, {"output": text}).points), "칼리 도구 결과"
        except ValueError:
            pass                                   # 도구 결과 모양이 아니면 URL 목록으로 다시 본다
    return surface_import.run(target, {"urls": text}), "URL 목록"


def run(target, params):
    mode = params.get("mode") or "auto"
    text = (params.get("paste") or "").strip()
    points = []
    if text:
        got, _kind = from_paste(target, text)
        points += got
    elif mode == "paste":
        raise ValueError("① 붙여 넣기 칸이 비어 있습니다 — 붙여 넣을 것이 없으면 '② 자동 수집까지' 를 고르세요")
    if mode in ("auto", "deep"):
        p = {**_defaults(surface_discover.META), "max_pages": params.get("max_pages") or "30"}
        points += surface_discover.run(target, p)
    if mode == "deep":
        p = {**_defaults(content_discovery.META), "wordlist": params.get("wordlist") or "web-common.txt"}
        points += content_discovery.run(target, p)
    return points
