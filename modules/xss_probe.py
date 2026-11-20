"""고른 지점마다 반사형 XSS 를 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

모듈은 취약점별로 수집한 지점에 '전부 때리는' 구조다(사용자 결정 11-20). 지점마다 먼저 넣은 값이
응답에 돌아오는 구간인지 보고, 후보로 남은 지점에만 페이로드를 늘려 넣는다. 확인되면 멈춘다.
저장형(글 등록)은 다루지 않는다 — 데이터가 남기 때문에 따로 승인받는 모듈(커뮤니티 저장형 XSS)의 몫이다.

  ① 받는 구간  고유 표식이 응답에 돌아오는가. 안 돌아오면 후보 아님 → 안전으로 끝
  ② 기본       태그가 그대로 돌아오는가(<표식>), 속성 탈출("><표식>)
  ③ 심화       이벤트 처리기 붙이기(" autofocus onfocus=…), 스크립트 블록 탈출(</script><표식>)
  ④ 우회       대소문자 섞기, 공백 대신 /, 꺾쇠 HTML 인코딩 뒤 되돌아오는지, javascript: 링크
보내는 값은 표식 이름을 쓴 무해한 태그·속성이다 — 브라우저에서 실제로 돌아가는지는 따로 확인한다.
"""
import re

from dashboard import probe
from dashboard.core import Check

META = {
    "id": "xss_probe",
    "name": "XSS 점검",
    "category": "입력 검증",
    "kisa": ["XS"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "XSS",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "kind": "active",
    "stage": "probe",
    "severity": "medium",
    "attack": [{"tactic": "TA0002", "technique": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
               {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"}],
    "description": "고른 지점마다 **① 받는 구간**(표식이 응답에 돌아오는지)을 먼저 보고, 후보에만 "
                   "② 기본(태그·속성 탈출) → ③ 심화(이벤트 처리기·스크립트 탈출) → ④ 우회(대소문자·/·인코딩·javascript:) 순서로 넣습니다. "
                   "저장형은 다루지 않습니다.",
    "params": [
        {"name": "methods", "need": "required", "label": "보낼 메서드", "default": "GET",
         "help": "POST 를 넣으면 폼을 실제로 제출합니다 — 테스트 계정·테스트 행에서만"},
    ],
}
_REC = ("출력 위치에 맞게 인코딩합니다(본문은 HTML 엔티티, 속성은 따옴표 포함 인코딩, 스크립트 안은 JS 문자열 이스케이프). "
        "템플릿 자동 이스케이프를 끄지 않았는지, innerHTML 로 넣지 않는지 확인하고 CSP 를 둡니다.")


def stages(t):
    return {
        "basic": [(f"<{t}>", "태그"), (f"\"><{t}>", "속성 탈출 후 태그")],
        "deep": [(f"\" autofocus onfocus={t} x=\"", "이벤트 처리기"), (f"</script><{t}>", "스크립트 블록 탈출")],
        "bypass": [(f"<{t.upper()}>", "대소문자"), (f"<{t}/x=1>", "공백 대신 /"),
                   (f"%3C{t}%3E", "꺾쇠 인코딩"), (f"javascript:{t}", "javascript: 링크")],
    }


def needle(value, t):
    """응답에서 무엇이 보여야 '실행될 수 있는 모양으로 돌아왔다' 고 하는지.

    특수문자가 없는 값(인코딩된 꺾쇠, javascript:)은 걸러지지 않아도 그대로 돌아오므로 그대로 찾으면
    안전한 화면도 취약으로 잡는다. 인코딩은 서버가 풀어서 진짜 태그가 돼 돌아왔을 때만, javascript: 는
    href·src·action 속성 값 자리에 들어갔을 때만 본다.
    """
    if value.startswith("%3C"):
        return re.compile(re.escape(f"<{t}>"))
    if value.startswith("javascript:"):
        return re.compile(r"(?:href|src|action)\s*=\s*[\"']?" + re.escape(value), re.I)
    return re.compile(re.escape(value))


def run(target, points, params):
    allowed = {m.strip().upper() for m in params.get("methods", "GET").split(",") if m.strip()}
    out = []
    for p in points:
        if p.method not in allowed:
            continue
        lad = probe.Ladder(p)
        t = probe.marker()
        r0 = probe.send(p, t)
        lad.note("screen", f"표식: {probe.request_line(p, t)} → {r0.status}")
        if t not in r0.body:
            lad.note("screen", "표식이 응답에 돌아오지 않음 — 받는 구간이 아님(후보 제외)")
        else:
            lad.note("screen", f"표식이 응답에 돌아옴({probe.CONTEXT_LABEL[probe._context(r0.body, r0.body.find(t))]}) — 후보")

            def confirm(r, value):
                m = needle(value, t).search(r.body)
                if m:
                    return ("반사형 XSS 후보 — 넣은 값이 실행될 수 있는 모양으로 돌아옴",
                            f"응답에: …{probe._excerpt(r.body, m.start(), m.end() - m.start())}…")
                return None
            for stage, payloads in stages(t).items():
                if lad.try_payloads(stage, payloads, confirm):
                    break
            if not lad.done:
                lad.maybe("bypass", r0, "표식은 돌아오지만 특수문자는 걸러짐 — 필터가 있음. 다른 모양으로 더 볼 곳")
        out.append(Check(point=p, verdict=lad.verdict, evidence="\n".join(lad.lines), response=lad.response or r0,
                         title=lad.title, recommendation=_REC))
    return out
