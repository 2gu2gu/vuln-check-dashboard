"""고른 지점마다 남의 자원이 열리는지 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

노션 '웹 서비스 취약점 목록' 의 AUTH 묶음에 **번호만 바꿔 남의 것을 보는** 건이 여럿이다
(구매이력 orderId, 강의 과제 aid, Q&A 비밀글 qid). 이름은 IDOR 이다 — 서버가 '이 번호의 자원' 을
돌려줄 때 '이 사람의 것인가' 를 안 보는 것이다.

  ① 받는 구간  원래 값으로 한 번. 2xx 가 아니거나 본문이 거의 없으면 견줄 것이 없다
  ② 기본       번호를 바꿔 본다(±1, 1, 9999). 2xx 로 **내용이 다른 것** 이 오면 남의 자원일 수 있다 → 잠재
  ③ 심화       다른 계정 토큰이 있으면 **원래 번호를** 그 토큰으로 요청한다. 같은 내용이 오면 확정 → 취약
  ④ 우회       인증을 아예 떼고 원래 번호를 요청한다. 열리면 취약

번호만 보는 모듈이라 숫자(또는 UUID)처럼 생긴 지점만 돈다. 읽기(GET)만 보낸다.

**잠재와 취약을 가르는 것은 다른 계정이다.** 토큰 하나로는 '열린 자원이 내 것인지 남의 것인지' 를 알 수
없다 — ③ 에 두 번째 계정을 넣어야 확정된다.
"""
import re
from urllib.parse import quote, urlencode

from dashboard import core, probe
from dashboard.core import Check

META = {
    "id": "idor_probe",
    "name": "남의 자원 접근(IDOR) 점검",
    "category": "인증·권한",
    "kisa": ["IN", "FD"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "AUTH",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "kind": "active",
    "stage": "probe",
    "unit": "param",
    "severity": "high",
    "attack": [{"tactic": "TA0007", "technique": "T1087", "name": "Account Discovery"},
               {"tactic": "TA0009", "technique": "T1213", "name": "Data from Information Repositories"}],
    "description": "고른 지점의 **번호를 바꿔** 남의 자원이 열리는지 봅니다. ② 다른 번호가 2xx 로 다른 내용이면 잠재, "
                   "③ **두 번째 계정 토큰**으로 같은 번호가 열리면 취약, ④ 인증을 떼고도 열리면 취약입니다. "
                   "숫자·UUID 처럼 생긴 지점만 돌고 읽기(GET)만 보냅니다.",
    "needs": [
        {"kind": "account", "required": True,
         "why": "자기 자원을 기준으로 남의 번호를 견주는 점검입니다",
         "how": "대상 탭의 **2. 인증** 에서 토큰을 넣습니다. 확정하려면 ③ 칸에 **다른 계정** 토큰도 넣으세요"},
    ],
    "params": [
        {"name": "other_auth", "need": "optional", "label": "③ 다른 계정의 인증 헤더 한 줄", "default": "",
         "placeholder": "Authorization: Bearer eyJ…",
         "help": "다른 계정으로 같은 번호를 요청해 봅니다. 이것이 있어야 '잠재' 가 '취약' 으로 확정됩니다."},
    ],
}
_REC = ("자원을 돌려주기 전에 **토큰의 사용자 번호와 자원의 소유자 번호가 같은지** 서버에서 확인합니다. "
        "번호를 추측하기 어렵게 만드는 것(UUID)은 보조 수단일 뿐 권한 검증을 대신하지 않습니다.")

NUMBER = re.compile(r"^\d{1,12}$")
UUIDISH = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I)
MIN_BODY = 40  # 이보다 짧은 응답은 견줄 내용이 없다고 본다
OPEN = range(200, 300)


def targets_of(sample: str):
    """바꿔 볼 번호들 → [(값, 설명)]. 번호처럼 생기지 않으면 빈 목록."""
    s = (sample or "").strip()
    if NUMBER.match(s):
        n = int(s)
        out = [(str(n + 1), "다음 번호"), ("1", "맨 앞 번호"), ("9999", "멀리 있는 번호")]
        if n > 1:
            out.insert(1, (str(n - 1), "앞 번호"))
        return [(v, k) for v, k in out if v != s]
    if UUIDISH.match(s):
        # 마지막 글자만 바꿔 다른 자원을 가리키게 한다(UUID 는 더하기가 뜻이 없다)
        return [(s[:-1] + ("0" if s[-1] != "0" else "1"), "끝 글자 바꾼 번호")]
    return []


def parse_line(text: str):
    """'이름: 값' 한 줄 → {이름: 값}. 빈 줄·모양이 아닌 줄은 버린다."""
    out = {}
    for line in (text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def _same_body(a, b) -> bool:
    """두 응답이 **같은 자원** 인가. 길이가 아니라 본문 글자를 견준다.

    번호만 바꾼 페이지는 길이가 똑같고 번호만 다르기 일쑤라, 길이 비교로는 갈리지 않는다(11-20).
    """
    return a.status == b.status and a.body == b.body


def run(target, points, params):
    other = parse_line(params.get("other_auth"))
    out = []
    for p in points:
        if p.method != "GET":
            continue
        shots = targets_of(p.sample)
        if not shots:
            continue
        lad = probe.Ladder(p)
        r0 = probe.send(p, p.sample)
        lad.note("screen", f"원래 값: {probe.request_line(p, p.sample)} → {r0.status} · {len(r0.body)}B")
        if r0.status not in OPEN or len(r0.body) < MIN_BODY:
            lad.note("screen", "원래 값으로도 내용이 오지 않음 — 견줄 것이 없음(후보 제외)")
        else:
            # ② 기본 — 번호를 바꿔 본다
            hit = None
            for value, kind in shots:
                r = probe.send(p, value)
                lad.note("basic", f"{kind}({value}): → {r.status} · {len(r.body)}B")
                if r.status in OPEN and len(r.body) >= MIN_BODY and not _same_body(r0, r):
                    lad.maybe("basic", r, f"{kind}({value})가 2xx 로 **다른 내용** 을 돌려줌 — 남의 자원일 수 있음")
                    hit = (value, kind, r)
                    break
            if not hit:
                lad.note("basic", "바꿔 본 번호는 열리지 않거나 같은 화면 — 번호로 남의 자원을 집지는 못함")
            # ③ 심화 — 다른 계정 토큰으로 원래 번호
            if other:
                o = _send_as(p, p.sample, other)
                lad.note("deep", f"다른 계정으로 원래 값: → {o.status} · {len(o.body)}B")
                if o.status in OPEN and _same_body(r0, o):
                    lad.hit("deep", o, "남의 자원 접근(IDOR) — 다른 계정 토큰으로 같은 자원이 열림",
                            "내 계정이 본 것과 **같은 응답** 이 다른 계정 토큰으로도 왔다 — 소유자 확인이 없다")
                elif o.status in OPEN:
                    lad.note("deep", "다른 계정으로도 2xx 지만 내용이 다름 — 계정마다 자기 자원을 받는 모양")
                else:
                    lad.note("deep", f"다른 계정으로는 {o.status} — 소유자 확인이 있다")
            else:
                lad.note("deep", "다른 계정 토큰이 없어 확정하지 못함 — ③ 칸에 넣으면 취약·안전이 갈린다")
            # ④ 우회 — 인증을 떼고
            if not lad.done:
                a = _send_as(p, p.sample, None)
                lad.note("bypass", f"인증 없이 원래 값: → {a.status} · {len(a.body)}B")
                if a.status in OPEN and len(a.body) >= MIN_BODY and _same_body(r0, a):
                    lad.hit("bypass", a, "인증 없이 자원이 열림", "인증 헤더를 떼도 같은 응답이 왔다")
        out.append(Check(point=p, verdict=lad.verdict, evidence="\n".join(lad.lines), response=lad.response or r0,
                         title=lad.title, severity="high" if lad.verdict == "vuln" else "medium", recommendation=_REC))
    return out


def _send_as(point, value, headers):
    """point 의 값 자리에 value 를 넣어, **주어진 인증 헤더로**(headers=None 이면 인증 없이) 보낸다.

    probe.send 는 대상 인증 헤더를 그대로 붙인다. 여기서는 '누구로 보내는지' 가 점검의 핵심이라
    대상 인증을 떼고(auth=False) 헤더를 직접 지정한다.
    """
    if point.place == "path":
        url = re.sub(r"\{[^}/]+\}", "1", point.url.replace("{" + point.param + "}", quote(value, safe="")))
    else:
        url = point.url + "?" + urlencode({**point.fields, point.param: value})
    return core.fetch(url, headers=headers or None, auth=False)
