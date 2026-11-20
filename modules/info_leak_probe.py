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
        # ④ 우회 — 메서드
        o = core.fetch(p.url, method="OPTIONS")
        allow = (o.header("Allow") or o.header("Access-Control-Allow-Methods")).upper()
        opened = [m for m in DANGER if m in allow]
        note("bypass", f"OPTIONS → {o.status}" + (f" · Allow: {allow}" if allow else ""))
        if opened and verdict == "safe":
            verdict, keep, title = "potential", o, f"위험한 메서드 허용({', '.join(opened)})"
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
