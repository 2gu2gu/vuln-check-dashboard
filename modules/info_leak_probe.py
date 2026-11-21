"""고른 주소마다 정보 노출을 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

모듈은 취약점별로 수집한 지점에 '전부 때리는' 구조다(사용자 결정 11-20). 예전 '서버 정보 노출' 은 첫 페이지
하나만 봤다 — 이제 모은 주소마다 본다(주소 단위, unit=endpoint).

  ① 받는 구간  주소가 응답하는가(연결·5xx 만 아니면 후보). 응답 자체가 없으면 끝
  ② 기본       응답 헤더(Server·X-Powered-By·X-AspNet-Version)·generator 메타·본문의 제품 버전
  ③ 심화       오류를 일부러 낸다 — 경로 뒤에 깨진 글자({, %), 배열 파라미터(a[]=), 아주 긴 값 → 스택 트레이스·버전이 새는가
  ④ 우회       OPTIONS 의 Allow 에 PUT·DELETE·TRACE, TRACE 가 요청을 그대로 되돌리는가
판정: 스택 트레이스·TRACE 되돌림 → 취약, 버전·위험 메서드 허용 → 잠재(정보로 남김), 아무것도 없으면 안전.
"""
import re
import uuid

from dashboard import core
from dashboard.core import Check

META = {
    "id": "info_leak_probe",
    "name": "정보 노출 점검",
    "category": "정보 수집",
    "kisa": ["IL", "EP", "WM"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 제안값 — 사람이 고쳐 쓴다
    "vuln": "정보노출",
    "kind": "active",
    "stage": "probe",
    "unit": "endpoint",
    "severity": "medium",
    "attack": [{"tactic": "TA0043", "technique": "T1592.002", "name": "Gather Victim Host Information: Software"}],
    "description": "고른 **주소마다** ① 응답하는지 보고, ② 헤더·본문의 제품 버전 → ③ 일부러 낸 오류 페이지의 스택 트레이스·버전 → "
                   "④ OPTIONS·TRACE 로 위험한 메서드가 열려 있는지 봅니다.",
    "params": [],
}

VERSION = re.compile(r"\d+\.\d+")
PRODUCT_VERSION = re.compile(r"(Apache Tomcat|nginx|Apache|Jetty|Microsoft-IIS|Express|Spring Boot|PHP|Next\.js)[/ ]v?(\d+(?:\.\d+)+)", re.I)
STACK_TRACE = re.compile(r"(java\.lang\.\w+(Exception|Error)|\bat (org|com|java)\.[\w.$]+\(|Traceback \(most recent call last\)"
                         r"|org\.springframework\.\w+|Whitelabel Error Page)")
GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
# 응답 본문에 그대로 박혀 나오는 비밀값 모양(팀원 도구 piroim/site-scanner 의 정규식을 참고해 다듬었다).
# 이름만 맞은 것으로는 적지 않는다 — 값의 길이·모양까지 맞아야 판정한다.
SECRETS = [
    ("AWS 접근 키", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("JWT 토큰", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")),
    ("개인 키", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("API 키", re.compile(r"(?:api[_-]?key|access[_-]?key|client[_-]?secret)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})", re.I)),
    ("비밀번호", re.compile(r"(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']([^\"'\s]{4,})[\"']", re.I)),
    ("DB 접속 문자열", re.compile(r"\b(?:jdbc:[a-z]+|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s\"'<>]{6,}", re.I)),
]
# Next.js 앱 라우터는 화면을 되살릴 데이터를 통째로 실어 보낸다. 없는 경로의 응답까지 그러면
# 라우트 목록과 빌드 번호가 그대로 드러난다(노션 '정보노출' 에 같은 건이 있다).
RSC_PAYLOAD = re.compile(r"self\.__next_f\.push\(|__NEXT_DATA__")
DANGER = ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
_REC = ("응답 헤더에서 제품명·버전을 지우고(nginx server_tokens off, Tomcat server 속성), 기본 오류 페이지 대신 사용자 정의 "
        "오류 페이지를 쓰며 예외 상세를 응답에 싣지 않습니다. 쓰지 않는 메서드(TRACE·PUT·DELETE)는 막습니다.")


def run(target, points, params):
    out = []
    for p in points:
        lines, verdict, keep, title = [], "safe", None, ""

        def note(stage, text):
            lines.append(f"{ {'screen': '① 받는 구간', 'basic': '② 기본', 'deep': '③ 심화', 'bypass': '④ 우회'}[stage] } {text}")

        r = core.fetch(p.url)
        note("screen", f"GET {p.url} → {r.status} · {len(r.body)}B")
        if r.status == 0:
            note("screen", "응답이 없음 — 볼 것이 없음(후보 제외)")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r))
            continue
        keep = r
        # ② 기본 — 헤더·메타·본문 버전
        for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
            val = r.header(name)
            if val:
                note("basic", f"{name}: {val}" + (" (버전)" if VERSION.search(val) else ""))
                if VERSION.search(val):
                    verdict, title = "potential", f"{name} 헤더에 버전 노출"
        m = GENERATOR.search(r.body)
        if m:
            note("basic", f'generator 메타: {m.group(1)}')
        m = PRODUCT_VERSION.search(r.body)
        if m:
            note("basic", f"본문에 제품 버전: {m.group(0)}")
            verdict, title = "potential", "본문에 제품 버전 노출"
        for kind, pat in SECRETS:
            sm = pat.search(r.body)
            if sm:
                # 값을 가리지 않는다 — 자체 실습 환경이고, 가리면 맞는 값인지 확인할 수 없다(core.fetch 와 같은 기준)
                note("basic", f"본문에 {kind} 모양: …{core.excerpt(sm.group(0), 120)}…")
                verdict, keep, title = "vuln", r, f"응답 본문에 {kind} 노출"
                break
        # ③ 심화 — 일부러 오류를 낸다
        tag = uuid.uuid4().hex[:6]
        for url, kind in ((p.url.rstrip("/") + "/%7B" + tag, "깨진 경로 글자"), (p.url + "%", "끝에 %"),
                          (p.url + "?a[]=" + tag + "&a=" + tag, "배열 파라미터"), (p.url + "?q=" + "A" * 3000, "아주 긴 값")):
            e = core.fetch(url)
            note("deep", f"{kind}: → {e.status} · {len(e.body)}B")
            st = STACK_TRACE.search(e.body)
            if st:
                note("deep", f"오류 페이지에 스택 트레이스: …{st.group(0)}…")
                verdict, keep, title = "vuln", e, "오류 페이지에 스택 트레이스 노출"
                break
            pv = PRODUCT_VERSION.search(e.body)
            if pv and verdict == "safe":
                note("deep", f"오류 페이지에 서버 버전: {pv.group(0)}")
                verdict, keep, title = "potential", e, "오류 페이지에 서버 버전 노출"
        # 없는 경로도 화면 데이터를 통째로 돌려주는가(Next.js 앱 라우터)
        miss = core.fetch(p.url.rstrip("/") + "/zz" + tag)
        note("deep", f"없는 경로: → {miss.status} · {len(miss.body)}B")
        if verdict == "safe" and len(miss.body) > 2000 and RSC_PAYLOAD.search(miss.body):
            note("deep", "없는 경로의 응답에 화면 복원 데이터(__next_f·__NEXT_DATA__)가 통째로 들어 있음 — 라우트·빌드 번호가 드러난다")
            verdict, keep, title = "potential", miss, "없는 경로가 화면 데이터를 통째로 응답"
        # ④ 우회 — 메서드
        o = core.fetch(p.url, method="OPTIONS")
        allow = (o.header("Allow") or o.header("Access-Control-Allow-Methods")).upper()
        opened = [m for m in DANGER if m in allow]
        note("bypass", f"OPTIONS → {o.status}" + (f" · Allow: {allow}" if allow else ""))
        if opened and verdict == "safe":
            verdict, keep, title = "potential", o, "위험한 메서드 허용"   # 어떤 메서드인지는 근거에
        t = core.fetch(p.url, method="TRACE", headers={"X-Probe-" + tag: tag})
        note("bypass", f"TRACE → {t.status}")
        if t.status == 200 and tag in t.body:
            note("bypass", "TRACE 가 보낸 요청을 그대로 되돌림")
            verdict, keep, title = "vuln", t, "TRACE 메서드가 요청을 되돌림"
        if verdict == "safe":
            note("bypass", "버전·스택 트레이스·위험 메서드가 보이지 않음")
        out.append(Check(point=p, verdict=verdict, evidence="\n".join(lines), response=keep, title=title,
                         severity="medium" if verdict == "vuln" else "low", recommendation=_REC))
    return out
