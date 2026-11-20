"""점검 기준 — 주요정보통신기반시설 웹 21항목(KISA 코드)과 OWASP Top 10 2025.

결과보고서 양식(`01_제출물/결과보고서_양식/1_결과보고서_양식.md` 2-2절)의 표를 그대로 옮겼다.
코드·이름·OWASP 매핑을 바꾸려면 그 표와 같이 바꾼다 — 보고서와 대시보드가 같은 말을 써야 한다.
OWASP 매핑은 그 표에 적힌 대로 팀 자체 판단이다.

모듈은 META["kisa"] 에 자기가 보는 항목 코드를 적는다(여럿 가능). OWASP 분류는 코드에서 정해진다.
"""

# OWASP Top 10 2025 — (키, 화면 이름)
OWASP_2025 = [
    ("A01", "Broken Access Control"),
    ("A02", "Security Misconfiguration"),
    ("A03", "Software Supply Chain Failures"),
    ("A04", "Cryptographic Failures"),
    ("A05", "Injection"),
    ("A06", "Insecure Design"),
    ("A07", "Authentication Failures"),
    ("A08", "Software or Data Integrity Failures"),
    ("A09", "Security Logging and Alerting Failures"),
    ("A10", "Mishandling of Exceptional Conditions"),
]
OWASP_NAME = dict(OWASP_2025)

# KISA 코드 → (점검 항목, OWASP 키). 순서는 양식 표 순서.
KISA = {
    "CI": ("코드 인젝션", "A05"),
    "SI": ("SQL 인젝션", "A05"),
    "DI": ("디렉터리 인덱싱", "A02"),
    "EP": ("에러 페이지 적용 미흡", "A10"),
    "IL": ("정보 누출", "A02"),
    "XS": ("크로스사이트 스크립트", "A05"),
    "CF": ("크로스사이트 요청 위조(CSRF)", "A01"),
    "SF": ("서버사이드 요청 위조(SSRF)", "A01"),
    "BF": ("약한 비밀번호 정책", "A07"),
    "IA": ("불충분한 인증 절차", "A07"),
    "IN": ("불충분한 권한 검증", "A01"),
    "PR": ("취약한 비밀번호 복구 절차", "A07"),
    "PV": ("프로세스 검증 누락", "A06"),
    "FU": ("악성 파일 업로드", "A06"),
    "FD": ("파일 다운로드", "A01"),
    "IS": ("불충분한 세션 관리", "A07"),
    "SN": ("데이터 평문 전송", "A04"),
    "CC": ("쿠키 변조", "A07"),
    "AE": ("관리자 페이지 노출", "A01"),
    "AU": ("자동화 공격", "A07"),
    "WM": ("불필요한 Method 악용", "A02"),
}


def check_kisa(codes) -> list:
    """META["kisa"] 검사. 없는 코드를 적으면 모듈이 안 올라간다 — 보고서와 말이 갈라지면 안 된다."""
    codes = list(codes or [])
    bad = [c for c in codes if c not in KISA]
    if bad:
        raise ValueError(f"kisa 에 없는 코드: {', '.join(bad)} (쓸 수 있는 것: {', '.join(KISA)})")
    return codes


def owasp_of(codes) -> list:
    """KISA 코드들 → OWASP 키들(순서 유지, 중복 없음)."""
    out = []
    for c in codes:
        k = KISA[c][1]
        if k not in out:
            out.append(k)
    return out
