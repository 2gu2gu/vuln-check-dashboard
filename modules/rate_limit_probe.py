"""고른 주소마다 요청 수 제한이 있는지 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

노션 '웹 서비스 취약점 목록' 의 Insecure Design 묶음에 **막는 장치가 없어 계속 넣어 볼 수 있는** 건이
둘 있다(로그인 페이지 레이트리밋 전무, 쿠폰 코드 전사공격). 둘 다 '같은 주소에 빠르게 여러 번 보내고
막히는지 보는 것' 으로 드러난다.

  ① 받는 구간  한 번 보내 응답을 본다. 응답이 없으면 끝.
               **없는 길이면 셀 것이 없다** — 404·405 거나 앱 화면 틀이 돌아오면 그 주소에는
               횟수를 셀 동작이 없다(11-21 실측: 관리자 웹의 `/{Ed}` 같은 가짜 경로 4곳이
               Next.js 404 쪽을 12번 받고 '제한 없음' 으로 잘못 잡혔다)
  ② 기본       정한 횟수만큼 잇달아 보낸다. 429·503·Retry-After·'잠시 후'·lock 같은 신호가 나오는가
  ③ 심화       막히지 않았다면 응답 시간이 늘어나는가(느리게 하는 방어도 방어다)
  ④ 우회       막혔다면 X-Forwarded-For 를 바꿔 지나가는가 — 앞단이 IP 로만 세면 헤더 한 줄로 풀린다

판정: 신호가 전혀 없음 → 취약. 느려지기만 함 → 잠재. 429·락아웃 → 안전(단 ④ 로 풀리면 취약).

**요청을 여러 번 보낸다.** 로그인·쿠폰처럼 실패 횟수를 세는 주소에 POST 로 돌리면 **테스트 계정이
잠길 수 있다.** 비밀번호 자리에는 틀린 값을 넣는다 — 맞히려는 것이 아니라 막는 장치가 있는지 보는
것이다.
"""
import time

from dashboard import core, probe
from dashboard.core import Check

META = {
    "id": "rate_limit_probe",
    "name": "요청 수 제한 점검",
    "category": "인증·권한",
    "kisa": ["AU", "BF"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "Insecure Design",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
    "kind": "active",
    "stage": "probe",
    "unit": "endpoint",
    "severity": "medium",
    "attack": [{"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
               {"tactic": "TA0006", "technique": "T1110.004", "name": "Brute Force: Credential Stuffing"}],
    "description": "고른 **주소마다** 정한 횟수만큼 잇달아 보내 **막는 장치가 있는지** 봅니다. "
                   "429·Retry-After·락아웃 신호가 전혀 없으면 취약, 응답만 느려지면 잠재입니다. "
                   "막혔으면 ④ X-Forwarded-For 를 바꿔 지나가는지도 봅니다. "
                   "**POST 로 돌리면 테스트 계정이 잠길 수 있습니다** — 비밀번호 자리에는 틀린 값을 넣으세요.",
    "params": [
        {"name": "tries", "need": "required", "label": "보낼 횟수", "default": "20", "type": "int",
         "help": "20 회면 보통 레이트리밋이 걸립니다. 너무 크게 두지 마세요."},
        {"name": "method", "need": "required", "label": "메서드", "default": "GET", "type": "select",
         "options": [{"value": "GET", "label": "GET (읽기 — 확인 칸 없이)"},
                     {"value": "POST", "label": "POST (로그인·쿠폰 — 확인 칸 필요)"}]},
        {"name": "body", "need": "optional", "label": "POST 본문(이름=값, 줄마다 하나)", "type": "textarea", "default": "",
         "placeholder": "email=test@example.com\npassword=wrong-on-purpose",
         "help": "비밀번호 자리에는 **틀린 값** 을 넣으세요. 맞히려는 점검이 아닙니다."},
    ],
}
_REC = ("주소마다 **IP 와 계정 양쪽으로** 짧은 시간 안의 횟수를 세어 막습니다(실패 5회면 잠금, 429 와 Retry-After 반환). "
        "앞단에서 IP 로만 세면 X-Forwarded-For 한 줄로 풀리므로, 신뢰할 수 있는 프록시가 넣은 값만 쓰도록 "
        "set_real_ip_from 을 지정하고 횟수는 애플리케이션에서도 셉니다. 로그인에는 느려지는 지연과 CAPTCHA 를 함께 둡니다.")

STAGE = {"screen": "① 받는 구간", "basic": "② 기본", "deep": "③ 심화", "bypass": "④ 우회"}
BLOCKED = (429, 503)
BLOCK_WORD = ("too many", "rate limit", "잠시 후", "잠금", "locked", "차단", "retry after", "제한")
MAX_TRIES = 50
NO_ROUTE = (404, 405, 410, 501)   # 길이 없거나 그 메서드를 안 받는다 — 셀 동작이 없다
SLOW = 2.0  # 마지막 응답이 처음보다 이 배 넘게 느려지면 '느리게 하는 방어' 로 본다


def _body(text: str):
    """'이름=값' 줄들 → dict. 비면 None."""
    out = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out or None


def _signal(r):
    """이 응답이 '막혔다' 는 신호인가 → 무엇을 보고 그랬는지, 아니면 None."""
    if r.status in BLOCKED:
        return f"{r.status}"
    if r.header("Retry-After"):
        return f"Retry-After: {r.header('Retry-After')}"
    low = r.body[:4000].lower()
    for w in BLOCK_WORD:
        if w in low:
            return f"본문에 '{w}'"
    return None


def run(target, points, params):
    tries = max(2, min(int(params.get("tries") or 20), MAX_TRIES))
    method = (params.get("method") or "GET").upper()
    data = _body(params.get("body"))
    shell = probe.app_shell(target)
    out = []
    for p in points:
        lines, verdict, keep, title = [], "safe", None, ""

        def note(stage, text):
            lines.append(f"{STAGE[stage]} {text}")

        def shot(extra=None):
            t0 = time.monotonic()
            r = core.fetch(p.url, method=method, data=data if method != "GET" else None, headers=extra)
            return r, time.monotonic() - t0

        r0, first = shot()
        note("screen", f"{method} {p.url} → {r0.status} · {len(r0.body)}B · {int(first * 1000)}ms")
        if r0.status == 0:
            note("screen", "응답이 없음 — 볼 것이 없음(후보 제외)")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r0))
            continue
        if r0.status in NO_ROUTE:
            note("screen", f"{r0.status} — 그 주소에 {method} 로 가는 길이 없다. 세어 볼 동작이 없음(후보 제외)")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r0))
            continue
        if shell is not None and r0.body == shell:
            note("screen", "첫 화면과 글자 하나까지 같은 응답 — 화면 틀이지 횟수를 세는 동작이 아니다(후보 제외)")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r0))
            continue
        keep = r0
        # ② 기본 — 잇달아 보낸다
        blocked_at, last = None, first
        codes = {r0.status: 1}
        for i in range(2, tries + 1):
            r, took = shot()
            last = took
            codes[r.status] = codes.get(r.status, 0) + 1
            sig = _signal(r)
            if sig:
                blocked_at, keep = (i, sig), r
                break
        shape = " · ".join(f"{k} {v}회" for k, v in sorted(codes.items()))
        note("basic", f"{tries} 회까지 보냄 → {shape}")
        if blocked_at:
            note("basic", f"{blocked_at[0]} 번째에 막힘({blocked_at[1]}) — 제한이 있다")
        else:
            note("basic", "끝까지 같은 응답 — 429·Retry-After·락아웃 신호가 전혀 없다")
            verdict, title = "vuln", "요청 수 제한 없음"   # 몇 회 보냈는지는 근거에
            # ③ 심화 — 느려지기라도 하는가
            note("deep", f"첫 응답 {int(first * 1000)}ms → 마지막 {int(last * 1000)}ms")
            if first and last / first >= SLOW:
                note("deep", "응답이 뚜렷하게 느려짐 — 느리게 하는 방어는 있다(막는 것은 아님)")
                verdict, title = "potential", "요청 수 제한 대신 지연만 있음"
        # ④ 우회 — 막혔다면 IP 를 바꿔 지나가는지
        if blocked_at:
            r, _ = shot({"X-Forwarded-For": "203.0.113.%d" % (len(p.url) % 250 + 1)})
            note("bypass", f"X-Forwarded-For 를 바꿔 한 번 더 → {r.status} · {len(r.body)}B")
            if not _signal(r):
                note("bypass", "헤더 한 줄로 제한을 지나감 — IP 로만 세고 있다")
                verdict, keep, title = "vuln", r, "요청 수 제한을 X-Forwarded-For 로 우회"
            else:
                note("bypass", "헤더를 바꿔도 막힘 — 제한이 IP 헤더에만 걸려 있지 않다")
        out.append(Check(point=p, verdict=verdict, evidence="\n".join(lines), response=keep, title=title,
                         severity="medium" if verdict == "vuln" else "low", recommendation=_REC))
    return out
