"""고른 주소마다 보안 헤더·쿠키·CORS 를 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

모듈은 취약점별로 수집한 지점에 '전부 때리는' 구조다(사용자 결정 11-20). 예전 'HTTP 보안 헤더' 는 페이지
하나만 봤다 — 이제 모은 주소마다 본다(주소 단위, unit=endpoint).

  ① 받는 구간  응답이 있는가. 화면(HTML)인지 데이터(JSON)인지 가린다 — 화면에만 해당하는 헤더가 있다
  ② 기본       HSTS(HTTPS), X-Content-Type-Options, Referrer-Policy, 화면이면 CSP·클릭재킹 방어
  ③ 심화       Set-Cookie 의 Secure·HttpOnly·SameSite
  ④ 우회       다른 출처(Origin: https://evil.example)를 보냈을 때 CORS 가 그대로 허용하는가(자격 증명 포함이면 더 위험)
판정: CORS 가 아무 출처나 허용·쿠키 속성 빠짐·HSTS 없음 → 취약, 그 밖의 헤더만 빠짐 → 잠재, 다 있으면 안전.
"""
from dashboard import core
from dashboard.core import Check

META = {
    "id": "header_probe",
    "name": "보안 헤더 점검",
    "category": "설정 점검",
    "kisa": ["SN", "CC"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "kind": "active",
    "stage": "probe",
    "unit": "endpoint",
    "severity": "medium",
    "attack": [{"tactic": "TA0043", "technique": "T1595.002", "name": "Vulnerability Scanning"},
               {"tactic": "TA0006", "technique": "T1539", "name": "Steal Web Session Cookie"}],
    "description": "고른 **주소마다** ① 응답·화면 종류를 보고, ② 보안 헤더(HSTS·CSP·nosniff·Referrer·클릭재킹) → "
                   "③ 쿠키 속성(Secure·HttpOnly·SameSite) → ④ 다른 출처를 보냈을 때 CORS 가 열리는지 봅니다.",
    "params": [],
}

EVIL = "https://evil.example"
_REC = ("HTTPS 응답에 Strict-Transport-Security, 모든 응답에 X-Content-Type-Options: nosniff·Referrer-Policy, 화면에는 CSP 와 "
        "X-Frame-Options(또는 frame-ancestors)를 붙입니다. 세션 쿠키에 Secure·HttpOnly·SameSite 를 붙이고, CORS 는 허용 목록의 "
        "출처만 돌려주며 자격 증명과 와일드카드를 함께 쓰지 않습니다.")


def run(target, points, params):
    out = []
    for p in points:
        lines, bad, minor = [], [], []

        def note(stage, text):
            lines.append(f"{ {'screen': '① 받는 구간', 'basic': '② 기본', 'deep': '③ 심화', 'bypass': '④ 우회'}[stage] } {text}")

        r = core.fetch(p.url)
        ctype = r.header("Content-Type").lower()
        page = "html" in ctype
        note("screen", f"GET {p.url} → {r.status} · {ctype or '종류 모름'}" + (" (화면)" if page else " (데이터)"))
        if r.status == 0:
            note("screen", "응답이 없음 — 볼 것이 없음(후보 제외)")
            out.append(Check(point=p, verdict="safe", evidence="\n".join(lines), response=r))
            continue
        https = r.url.startswith("https://")
        # ② 기본
        want = [("Strict-Transport-Security", https, bad), ("X-Content-Type-Options", True, minor),
                ("Referrer-Policy", True, minor), ("Content-Security-Policy", page, minor)]
        for name, applies, bucket in want:
            if applies and not r.header(name):
                bucket.append(name)
                note("basic", f"{name}: 없음")
        if page and not r.header("X-Frame-Options") and "frame-ancestors" not in r.header("Content-Security-Policy").lower():
            minor.append("클릭재킹 방어")
            note("basic", "X-Frame-Options·frame-ancestors: 없음")
        # ③ 심화 — 쿠키
        for raw in r.header_all("Set-Cookie"):
            name = raw.split("=", 1)[0].strip()
            attrs = [a.strip().lower() for a in raw.split(";")[1:]]
            missing = [k for k, ok in (("Secure", not https or "secure" in attrs), ("HttpOnly", "httponly" in attrs),
                                       ("SameSite", any(a.startswith("samesite") for a in attrs))) if not ok]
            if missing:
                bad.append(f"쿠키 {name}")
                note("deep", f"쿠키 {name}: {', '.join(missing)} 빠짐")
        # ④ 우회 — CORS
        c = core.fetch(p.url, headers={"Origin": EVIL})
        acao, cred = c.header("Access-Control-Allow-Origin"), c.header("Access-Control-Allow-Credentials").lower()
        note("bypass", f"Origin: {EVIL} → ACAO: {acao or '(없음)'}" + (f" · Credentials: {cred}" if cred else ""))
        if acao in (EVIL, "*") and (acao == EVIL or cred == "true"):
            bad.append("CORS 아무 출처 허용" + (" + 자격 증명" if cred == "true" else ""))
        verdict = "vuln" if bad else ("potential" if minor else "safe")
        if verdict == "safe":
            note("bypass", "보안 헤더·쿠키 속성·CORS 모두 괜찮음")
        title = ("보안 설정 미흡: " + ", ".join(bad + minor))[:120] if verdict != "safe" else ""
        out.append(Check(point=p, verdict=verdict, evidence="\n".join(lines), response=c if "CORS" in " ".join(bad) else r,
                         title=title, severity="medium" if verdict == "vuln" else "low", recommendation=_REC))
    return out
