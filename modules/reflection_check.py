"""지점마다 고유 표식 + 특수문자를 넣어 보내고, 응답에 그대로 돌아오는지 본다(XSS 후보 찾기).

스크립트를 실행하는 값은 보내지 않는다. 실제 페이로드 목록은 유형별 모듈에서 같은 틀로 늘린다.
"""
from dashboard import probe
from dashboard.core import Check

META = {
    "id": "reflection_check",
    "name": "입력값 반사 확인",
    "category": "입력 검증",
    # 반사형 XSS 의 전형값 — 피해자가 링크를 눌러야 하고 브라우저로 범위가 넘어간다
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    # 노션 '웹 서비스 취약점 목록' 의 취약점 유형 — 넣은 특수문자가 걸러지지 않고 본문·속성·스크립트 자리로 돌아오는지
    "vuln": "XSS",
    "kind": "active",
    "stage": "probe",
    "severity": "medium",
    "attack": [
        {"tactic": "TA0002", "technique": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
        {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
    ],
    "description": "표식과 ' \" < > 를 넣어 응답에 그대로 나오면 취약, 바뀌어 나오면 잠재, 안 나오면 안전. 반사 위치(본문·태그 속성·스크립트)도 남깁니다.",
    "params": [
        {"name": "methods", "label": "보낼 메서드", "default": "GET",
         "help": "POST 를 넣으면 폼을 실제로 제출합니다 — 글·데이터가 저장될 수 있으니 테스트 계정·테스트 행에서만"},
    ],
}

SPECIAL = "'\"<>"


def run(target, points, params):
    allowed = {m.strip().upper() for m in params.get("methods", "GET").split(",") if m.strip()}
    out = []
    for p in points:
        if p.method not in allowed:
            continue
        token = probe.marker()
        sent = token + SPECIAL
        r = probe.send(p, sent)
        verdict, ctx, excerpt = probe.judge_reflection(r.body, token, sent)
        lines = [f"{probe.request_line(p, sent)} → {r.status}"]
        if verdict == "safe":
            lines.append("응답에 표식 없음")
        else:
            lines += [f"반사 위치: {probe.CONTEXT_LABEL[ctx]}", f"…{excerpt}…"]
        out.append(Check(
            point=p, verdict=verdict, evidence="\n".join(lines), response=r,
            title=f"입력값이 그대로 반사됨({probe.CONTEXT_LABEL.get(ctx, '')})" if verdict == "vuln" else "",
            recommendation="출력 위치에 맞게 인코딩합니다(본문은 HTML 엔티티, 속성은 따옴표 포함 인코딩, 스크립트 안은 JS 문자열 이스케이프). "
                           "템플릿 자동 이스케이프를 끄지 않았는지, innerHTML 로 넣지 않는지 확인합니다."))
    return out
