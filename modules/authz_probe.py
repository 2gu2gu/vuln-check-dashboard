"""고른 주소마다 인증·인가를 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

노션 '웹 서비스 취약점 목록' 의 AUTH 묶음에서 가장 많은 모양이 **인증을 지나서 열리는 것** 이다
(미수강 강의 영상·자료 열람, 일반 유저의 강사센터 접근, Nginx location deny all 우회). 이 셋은 전부
같은 방법으로 드러난다 — 같은 주소를 **인증 있이 한 번, 떼고 한 번** 보내 응답을 견준다.

  ① 받는 구간  인증 헤더를 붙여 한 번. 2xx 가 아니면 견줄 것이 없다(후보 제외).
               **화면 틀(SPA 껍데기)도 여기서 뺀다** — React·Vue 앱은 어느 주소를 불러도 같은 index.html
               을 돌려주므로 '인증 없이 같은 응답' 이 늘 참이 된다. 권한은 뒤쪽 API 가 보는데 그건
               이 주소가 아니다(11-21 실측: /mypage·/instructor 가 똑같이 564바이트짜리 껍데기였다)
  ② 기본       인증 헤더를 떼고 같은 요청. 같은 응답이 오면 그 주소에는 인증이 없는 것이다
  ③ 심화       막혀 있을 때 **경로를 바꿔** 지나가는가 — Nginx location 은 경로를 글자로 맞추므로
               `//login`, `/login/`, `/./login`, `/LOGIN`, `/login;x`, `/%2e/login` 이 다른 경로가 된다
  ④ 우회       앞단이 경로로 막을 때 뒷단에 경로를 따로 알려 주는 헤더(X-Original-URL·X-Rewrite-URL)와
               메서드 바꿔치기(X-HTTP-Method-Override)로 지나가는가

판정: 인증 없이 같은 응답 · 경로 변형으로 차단 통과 → 취약. 응답이 다르지만 2xx → 잠재(내용 확인 필요).
읽기(GET)만 보낸다 — 데이터를 바꾸지 않는다.
"""
from urllib.parse import urlsplit, urlunsplit

from dashboard import core, probe
from dashboard.core import Check

META = {
    "id": "authz_probe",
    "name": "인증·인가 점검",
    "category": "인증·권한",
    "kisa": ["IA", "IN", "AE"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "AUTH",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "kind": "active",
    "stage": "probe",
    "unit": "endpoint",
    "severity": "high",
    # 권한 검증이 빠진 주소를 찾는 것이다. 호스트의 권한 제어(sudo·UAC)를 건드리는 T1548 이 아니다
    "attack": [{"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"}],
    "description": "고른 **주소마다** 인증 헤더를 **붙여 한 번, 떼고 한 번** 보내 응답을 견줍니다. "
                   "같은 응답이면 인증 없이 열리는 것입니다. 막혀 있으면 ③ 경로 변형(`//`·`/.`·대소문자·`;`·`%2e`)과 "
                   "④ 경로 알림 헤더(X-Original-URL)로 차단을 지나가는지 봅니다. 읽기(GET)만 보냅니다.",
    "needs": [
        {"kind": "account", "required": True,
         "why": "'인증 있이' 와 '인증 없이' 를 견주는 점검이라 대상에 인증 헤더가 있어야 합니다",
         "how": "대상 탭의 **2. 인증** 에서 로그인해 토큰을 받거나 Bearer·쿠키를 직접 넣습니다"},
    ],
    "params": [
        {"name": "same_pct", "need": "optional", "label": "같다고 볼 길이 차이(%)", "default": "5", "type": "int",
         "help": "인증 없이 받은 응답의 길이가 이 안이면 '같은 응답' 으로 봅니다."},
    ],
}
_REC = ("자원을 돌려주기 전에 **요청한 사람이 그 자원의 임자인지** 서버에서 확인합니다(토큰의 사용자 번호와 자원의 "
        "소유자 번호 비교). 화면을 감추거나 앞단(Nginx)에서 경로로 막는 것은 방어가 아닙니다 — 경로는 `//`·`/.`·"
        "대소문자·`;`·`%2e` 로 모양을 바꿔 지나갈 수 있으니, 막는 자리는 애플리케이션이어야 합니다.")

STAGE = {"screen": "① 받는 구간", "basic": "② 기본", "deep": "③ 심화", "bypass": "④ 우회"}
# Nginx location 은 정규화한 경로를 글자로 맞춘다 — 같은 자원을 가리키면서 글자만 다른 모양들
PATH_TRICKS = [("//{p}", "앞에 // 겹치기"), ("{p}/", "뒤에 / 붙이기"), ("/.{p}", "앞에 /. 붙이기"),
               ("{P}", "대소문자 바꾸기"), ("{p};x", "뒤에 ;x 붙이기"), ("/%2e{p}", "앞에 /%2e 붙이기")]
# 앞단이 경로로 막을 때, 뒷단에 '진짜 경로' 를 따로 알려 주는 헤더들(리버스 프록시 설정에서 흔하다)
HEADER_TRICKS = [("X-Original-URL", "원래 주소 헤더"), ("X-Rewrite-URL", "주소 바꾸기 헤더")]
OPEN = range(200, 300)


def _with_path(url: str, path: str) -> str:
    u = urlsplit(url)
    return urlunsplit((u.scheme, u.netloc, "", "", "")) + path + (("?" + u.query) if u.query else "")


def _same(a, b, pct: float) -> bool:
    """두 응답을 '같다' 고 볼지. 상태가 같고 길이 차이가 pct% 안이면 같은 화면으로 본다."""
    if a.status != b.status:
        return False
    big = max(len(a.body), len(b.body)) or 1
    return abs(len(a.body) - len(b.body)) * 100 / big <= pct


def run(target, points, params):
    pct = float(params.get("same_pct") or 5)
    have_auth = bool(core.auth_headers())
    shell = probe.app_shell(target)
    out = []
    for p in points:
        lines, verdict, keep, title = [], "safe", None, ""

        def note(stage, text):
            lines.append(f"{STAGE[stage]} {text}")

        r = core.fetch(p.url)
        note("screen", f"인증 있이: GET {p.url} → {r.status} · {len(r.body)}B")
        if not have_auth:
            note("screen", "대상에 인증 헤더가 없어 '있이·없이' 를 견줄 수 없음 — 대상 탭 '2. 인증' 에 넣고 다시 돌리세요")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r))
            continue
        if r.status not in OPEN:
            note("screen", f"인증 있이도 {r.status} — 견줄 것이 없음(후보 제외)")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r))
            continue
        if shell is not None and r.body == shell:
            note("screen", "첫 화면과 **글자 하나까지 같은 응답** — 이 주소는 화면 틀(SPA 껍데기)이다. "
                           "어느 주소를 불러도 같은 것이 오므로 '인증 없이 열린다' 고 말할 수 없다(후보 제외)")
            note("screen", "권한은 뒤쪽 API 가 본다 — 로그인한 뒤 HAR 을 떠서 그 API 주소를 모아 다시 돌리세요")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r))
            continue
        keep = r
        # ② 기본 — 인증 헤더를 떼고 같은 요청
        n = core.fetch(p.url, auth=False)
        note("basic", f"인증 없이: GET {p.url} → {n.status} · {len(n.body)}B")
        if n.status in OPEN and _same(r, n, pct):
            note("basic", "인증 있이와 **같은 응답** — 이 주소에는 인증이 없다")
            verdict, keep, title = "vuln", n, "인증 없이 열리는 주소"
        elif n.status in OPEN:
            note("basic", f"인증 없이도 {n.status} 지만 응답이 다름 — 내용을 보고 가려야 함")
            verdict, keep, title = "potential", n, "인증 없이도 응답하는 주소(내용 확인 필요)"
        else:
            note("basic", f"인증 없이는 {n.status} — 막혀 있음. 차단을 지나갈 수 있는지 본다")
            path = urlsplit(p.url).path or "/"
            # ③ 심화 — 경로 모양 바꾸기
            for shape, kind in PATH_TRICKS:
                trick = shape.format(p=path, P=path.upper())
                if trick == path:
                    continue
                t = core.fetch(_with_path(p.url, trick), auth=False)
                note("deep", f"{kind}: GET {trick} → {t.status} · {len(t.body)}B")
                if t.status in OPEN:
                    note("deep", "경로 모양만 바꿔 차단을 지나감 — 앞단이 경로를 글자로 막고 있다")
                    verdict, keep, title = "vuln", t, "경로 변형으로 차단 통과"   # 어떤 변형인지는 근거에
                    break
            # ④ 우회 — 경로 알림 헤더.
            # **첫 화면과 견준다.** 헤더를 안 따르면 그냥 첫 화면이 오는데, 그것이 막힌 응답(401)과
            # 다르다고 해서 '따랐다' 고 하면 안 된다. 11-21 실측에서 이 한 줄이 없어 /backend/mypage 등
            # 12건이 통째로 거짓 양성이 됐다(GET / 이 늘 564바이트 앱 껍데기를 돌려준다).
            if verdict == "safe":
                root = core.fetch(core.join(target.url, "/"), auth=False)
                for name, kind in HEADER_TRICKS:
                    t = core.fetch(core.join(target.url, "/"), headers={name: path}, auth=False)
                    note("bypass", f"{kind}: {name}: {path} → {t.status} · {len(t.body)}B "
                                   f"(헤더 없이 첫 화면은 {root.status} · {len(root.body)}B)")
                    if t.body == root.body:
                        note("bypass", "헤더를 넣으나 빼나 첫 화면이 그대로 옴 — 뒷단이 헤더를 따르지 않는다")
                        continue
                    if t.status in OPEN and len(t.body) and not _same(t, n, pct):
                        note("bypass", "헤더를 넣었더니 첫 화면과도 막힌 응답과도 다른 것이 왔다 — 뒷단이 경로를 따랐다")
                        verdict, keep, title = "vuln", t, "경로 알림 헤더로 차단 통과"
                        break
        if verdict == "safe":
            note("bypass", "인증 없이는 막히고, 경로 변형·경로 알림 헤더로도 지나가지 못함")
        out.append(Check(point=p, verdict=verdict, evidence="\n".join(lines), response=keep, title=title,
                         severity="high" if verdict == "vuln" else "medium", recommendation=_REC))
    return out
