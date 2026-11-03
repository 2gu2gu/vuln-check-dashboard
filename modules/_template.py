"""새 모듈 작성 틀. 이 파일을 복사해 이름을 바꾸면(앞의 _ 제거) 자동 등록된다.

어디에 둘까
  modules/xxx.py                     범용 — 어느 대상에나 쓸 수 있는 점검
  projects/<프로젝트>/modules/xxx.py   전용 — 그 프로젝트의 경로·구성을 아는 점검

모듈 단계(META "stage")
  check   (기본) run(target, params) → [Finding]          대상 하나를 통째로 점검 — 이 파일
  collect        run(target, params) → [Point]            표면 수집 — 예: modules/surface_crawl.py
  probe          run(target, points, params) → [Check]    표면 탭에서 고른 지점마다 판정 — 예: modules/reflection_check.py
  유형별 점검(SQLi·XSS·경로 조작 등)은 probe 로 만들면 표면 수집 결과를 그대로 받아 쓴다.
  값 넣어 보내기·반사 판정은 dashboard/probe.py 의 send()·judge_reflection() 을 쓴다.

지킬 것
  1. 요청은 반드시 core.fetch 로만 보낸다(범위 검사·리다이렉트 차단이 여기서 걸린다).
     requests/urllib 를 직접 쓰거나 기존 도구를 subprocess 로 부를 때는 대상 주소를
     scope.ensure_in_scope(url) 로 먼저 검사한다.
  2. 응답에 든 비밀값(쿠키 값, 토큰, .env 내용 등)은 evidence 에 넣지 않는다. 이름·상태코드·길이만.
  3. 대상에 쓰기·변경을 일으키거나 요청이 많은 모듈은 kind 를 "active" 로 둔다(실행 전 확인 체크).
  4. id 는 전체(범용+모든 프로젝트)에서 하나여야 한다.
"""
from dashboard.core import Finding, fetch

META = {
    "id": "robots_txt",                  # 고유 id (파일 이름과 같게)
    "name": "robots.txt 확인",
    "category": "정보 수집",              # 모듈 화면에서 보이는 분류
    "kind": "passive",                   # passive: 읽기만 / active: 실행 전 확인 필요
    "attack": [                          # 첫 항목이 기본 기법. 여러 개면 매트릭스 여러 칸에 보인다
        {"tactic": "TA0043", "technique": "T1595.003", "name": "Wordlist Scanning"},
    ],
    "description": "robots.txt 의 Disallow 경로를 모읍니다.",
    "params": [                          # 화면에 입력칸으로 뜬다. 값은 문자열로 들어온다
        {"name": "path", "label": "경로", "default": "/robots.txt"},
    ],
}


def run(target, params):
    """target: Target(id, name, url) / params: {이름: 문자열} → Finding 목록"""
    r = fetch(target.url + params.get("path", "/robots.txt"))
    if r.status != 200:
        return []
    paths = [line.split(":", 1)[1].strip() for line in r.body.splitlines()
             if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()]
    if not paths:
        return []
    return [Finding(
        title=f"robots.txt 에 숨긴 경로 {len(paths)}개",
        severity="info",                 # critical / high / medium / low / info
        location=r.url,
        evidence="\n".join(paths[:30]),
        recommendation="숨기려는 경로라면 robots.txt 대신 접근 제어로 막습니다.",
        # technique="T1595.003",         # 비우면 META attack 첫 항목
    )]
