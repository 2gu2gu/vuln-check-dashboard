"""고른 지점마다 저장형 XSS 를 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

반사형(`xss_probe`)은 보낸 응답에서 값을 찾는다. 저장형은 **보낸 뒤 다시 읽어서** 찾는다.
그래서 쓰기 지점(POST·PUT·PATCH)에만 돌고, 확인할 주소를 다시 GET 한다.

  ① 받는 구간  표식을 한 번 넣고, 쓰기 응답과 확인 주소에서 그 표식을 찾는다. 어디에도 없으면 후보 아님
  ② 기본       태그가 그대로 남는가(<표식>), 속성 탈출("><표식>)
  ③ 심화       이벤트 처리기(" autofocus onfocus=…), 스크립트 블록 탈출(</script><표식>)
  ④ 우회       대소문자 섞기, 공백 대신 /, 꺾쇠 인코딩, javascript: 링크

**글·댓글이 남는다.** 테스트 계정으로 자체 환경에서만 돌리고, 끝난 뒤 남은 글은 직접 지운다
(지우는 것까지 하는 건 새싹에듀 커뮤니티 전용 모듈의 몫이다 — 그쪽은 등록→확인→자동삭제를 한다).
"""
from dashboard import core, probe
from dashboard.core import Check
from modules.xss_probe import needle, stages

META = {
    "id": "stored_xss_probe",
    "name": "저장형 XSS 점검",
    "category": "입력 검증",
    "kisa": ["XS"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "XSS",
    # 저장되면 보는 사람 모두에게 돌아간다 — 반사형보다 영향이 넓다
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
    "kind": "active",
    "stage": "probe",
    "severity": "high",
    "attack": [{"tactic": "TA0002", "technique": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
               {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"}],
    "description": "고른 **쓰기 지점**(POST·PUT·PATCH)에 값을 넣고 **다시 읽어** 남아 있는지 봅니다. "
                   "① 표식이 남는 지점만 후보로 두고 ② 기본 → ③ 심화 → ④ 우회 순서로 넣습니다. "
                   "**글·댓글이 남습니다** — 테스트 계정으로 자체 환경에서만, 끝난 뒤 직접 지우세요.",
    "needs": [
        {"kind": "account", "required": False,
         "why": "글을 등록하려면 보통 로그인이 필요하고, 남는 데이터는 그 계정 이름으로 남습니다",
         "how": "테스트 계정으로 받은 토큰을 대상 탭의 인증 헤더에 넣습니다"},
    ],
    "params": [
        {"name": "write_ack", "need": "required", "label": "쓰기 허용 확인", "default": "",
         "help": "데이터가 남습니다. WRITE 를 적어야 실행됩니다."},
        {"name": "read_urls", "need": "optional", "label": "확인할 주소 (한 줄에 하나)", "type": "textarea", "default": "",
         "help": "비우면 그 지점의 주소를 GET 으로 다시 읽습니다. 글 목록·상세 주소를 적으면 거기서도 찾습니다."},
        {"name": "methods", "need": "required", "label": "보낼 메서드", "default": "POST,PUT,PATCH",
         "help": "쓰기 지점만 돕니다. GET 은 반사형(XSS 점검)의 몫입니다."},
    ],
}
_REC = ("저장할 때가 아니라 **보여 줄 때** 출력 위치에 맞게 인코딩합니다(본문은 HTML 엔티티, 속성은 따옴표 포함). "
        "저장 전 검사만으로는 막히지 않습니다. 허용 태그만 남기는 정화기(HTML sanitizer)를 쓰고 CSP 를 둡니다.")
MAX_READ = 5


def _read(urls):
    """확인할 주소들을 다시 읽는다 → [(주소, 응답)]."""
    return [(u, core.fetch(u)) for u in urls]


def run(target, points, params):
    if (params.get("write_ack") or "").strip().upper() != "WRITE":
        raise ValueError("쓰기 허용 확인 칸에 WRITE 를 적어야 실행됩니다 (글·댓글이 남습니다)")
    allowed = {m.strip().upper() for m in params.get("methods", "POST,PUT,PATCH").split(",") if m.strip()}
    extra = [u.strip() for u in (params.get("read_urls") or "").splitlines() if u.strip()][:MAX_READ]
    out = []
    for p in points:
        if p.method not in allowed:
            continue
        reads = extra or [p.url]
        lad = probe.Ladder(p)
        t = probe.marker()
        w0 = probe.send(p, t)
        lad.note("screen", f"표식 등록: {probe.request_line(p, t)} → {w0.status}")
        seen = [u for u, r in _read(reads) if t in r.body] if w0.status else []
        if t in w0.body:
            seen.insert(0, "쓰기 응답")
        if not seen:
            lad.note("screen", "다시 읽어도 표식이 없음 — 저장되지 않거나 보이는 자리가 아님(후보 제외)")
        else:
            lad.note("screen", f"표식이 남아 있음({', '.join(seen)}) — 후보")

            def confirm(w, value):
                for where, r in [("쓰기 응답", w), *_read(reads)]:
                    m = needle(value, t).search(r.body)
                    if m:
                        return ("저장형 XSS 후보 — 넣은 값이 저장돼 그대로 보임",
                                f"{where} 에: …{probe._excerpt(r.body, m.start(), m.end() - m.start())}…")
                return None
            for stage, payloads in stages(t).items():
                if lad.try_payloads(stage, payloads, confirm):
                    break
            if not lad.done:
                lad.maybe("bypass", w0, "표식은 남지만 특수문자는 걸러짐 — 저장 전·출력 때 필터가 있음")
        out.append(Check(point=p, verdict=lad.verdict, evidence="\n".join(lad.lines), response=lad.response or w0,
                         title=lad.title, severity="high" if lad.verdict == "vuln" else "medium", recommendation=_REC))
    return out
