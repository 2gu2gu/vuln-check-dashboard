"""HAR 가져오기: 브라우저나 Burp 가 실제로 주고받은 요청을 붙여 넣으면 표면에 올린다.

요청은 보내지 않는다. 화면을 직접 눌러 보며 생긴 요청이라 JS 를 읽어 짐작한 것보다 정확하다 —
메서드·쿼리·폼·JSON 본문 키·앱 전용 헤더가 그대로 있고, 응답 코드로 상태도 바로 안다.
Playwright 로 화면을 대신 눌러 보는 방식(기획안 3단계 선택)은 서버에 브라우저를 깔아야 해서
이것으로 대신했다(11-20). 부품은 dashboard/discovery.parse_har.
"""
from dashboard import discovery as dv
from modules.surface_discover import _to_points

META = {
    "id": "har_import",
    "name": "HAR 가져오기",
    "category": "표면 수집",
    "kind": "passive",
    "stage": "collect",
    "attack": [{"tactic": "TA0043", "technique": "T1594", "name": "Search Victim-Owned Websites"}],
    "description": "브라우저 개발자도구 **네트워크 탭 → HAR 로 저장**(또는 Burp 의 요청 목록 내보내기) 파일 내용을 붙여 넣으면 "
                   "실제로 오간 요청의 메서드·쿼리·폼·JSON 본문 키·앱 전용 헤더와 응답 코드를 표면에 올립니다. 요청은 보내지 않습니다.",
    "needs": [
        {"kind": "tool", "name": "브라우저 개발자도구 또는 Burp",
         "why": "대시보드가 화면을 대신 눌러 보지 않습니다 — 사람이 눌러 본 기록을 받습니다",
         "how": "F12 → 네트워크 탭에서 화면을 이것저것 눌러 본 뒤, 목록에서 오른쪽 클릭 → 'HAR 로 모두 저장'"},
    ],
    "params": [
        {"name": "har", "need": "required", "label": "HAR 내용 붙여 넣기", "type": "textarea", "default": "",
         "placeholder": '{"log": {"entries": [{"request": {"method": "GET", "url": "https://..."}, '
                        '"response": {"status": 200}}]}}'},
    ],
}


def run(target, params):
    text = (params.get("har") or "").strip()
    if not text:
        raise ValueError("HAR 파일 내용을 붙여 넣어 주세요")
    reg = dv.Registry()
    if not dv.parse_har(text, target.url, reg):
        raise ValueError("이 대상 주소로 간 요청이 HAR 에 없습니다 — 대상 주소와 HAR 의 주소가 같은지 보세요")
    return _to_points(reg)
