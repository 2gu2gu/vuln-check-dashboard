"""CVSS 3.1 기본 점수(Base Score).

팀 노션의 '웹 서비스 취약점 목록' 이 쓰는 형식 그대로다.

    CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N   →   6.5 (Medium)

**점수는 벡터에서 계산한다.** 손으로 따로 적으면 둘이 어긋난다 —
실제로 노션의 '공통 페이지 응답 내 세션 식별자 노출' 항목은 속성이 High 인데
본문의 영향도는 Medium(6.5) 로 적혀 있다(11-04 확인). 같은 자리에서 뽑으면 그런 일이 없다.

계산식은 CVSS v3.1 명세(FIRST) 그대로다. 여기서 다루는 것은 기본 점수뿐이고,
시간(Temporal)·환경(Environmental) 지표는 넣지 않았다 — 팀 양식이 기본 점수만 쓴다.
"""
import math
import re

VERSION = "CVSS:3.1"

# 지표 이름과 고를 수 있는 값. 화면의 고르는 칸이 이 순서로 만들어진다.
METRICS = [
    ("AV", "공격 경로", "Attack Vector", [
        ("N", "네트워크", "인터넷 너머에서 보낼 수 있다"),
        ("A", "인접 네트워크", "같은 망 안에서만"),
        ("L", "로컬", "그 장비에 들어가 있어야 한다"),
        ("P", "물리", "직접 만져야 한다"),
    ]),
    ("AC", "공격 난이도", "Attack Complexity", [
        ("L", "낮음", "조건 없이 매번 된다"),
        ("H", "높음", "준비나 운이 필요하다"),
    ]),
    ("PR", "필요 권한", "Privileges Required", [
        ("N", "없음", "로그인 없이 된다"),
        ("L", "낮음", "일반 사용자 계정이면 된다"),
        ("H", "높음", "관리자급이 필요하다"),
    ]),
    ("UI", "사용자 개입", "User Interaction", [
        ("N", "불필요", "피해자가 아무것도 안 해도 된다"),
        ("R", "필요", "피해자가 눌러 줘야 한다"),
    ]),
    ("S", "범위 변경", "Scope", [
        ("U", "그대로", "뚫린 구성요소 안에서 끝난다"),
        ("C", "바뀜", "다른 구성요소까지 넘어간다"),
    ]),
    ("C", "기밀성", "Confidentiality", [
        ("H", "높음", "중요한 것까지 다 읽힌다"),
        ("L", "낮음", "일부만 읽힌다"),
        ("N", "없음", "읽히지 않는다"),
    ]),
    ("I", "무결성", "Integrity", [
        ("H", "높음", "마음대로 고칠 수 있다"),
        ("L", "낮음", "일부만 고칠 수 있다"),
        ("N", "없음", "고칠 수 없다"),
    ]),
    ("A", "가용성", "Availability", [
        ("H", "높음", "멈출 수 있다"),
        ("L", "낮음", "느려지는 정도"),
        ("N", "없음", "영향 없다"),
    ]),
]
ORDER = [m[0] for m in METRICS]
CHOICES = {m[0]: [v[0] for v in m[3]] for m in METRICS}

# 명세의 가중치
W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# 필요 권한은 '범위 변경'에 따라 가중치가 달라진다
PR_W = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50}}

# 점수 → 등급. 노션 속성(Low·Medium·High)과 대시보드 심각도에 함께 쓴다.
BANDS = [(9.0, "critical", "Critical"), (7.0, "high", "High"),
         (4.0, "medium", "Medium"), (0.1, "low", "Low"), (0.0, "info", "None")]

_PART = re.compile(r"^([A-Z]{1,2}):([A-Z])$")


class BadVector(ValueError):
    """벡터 문자열이 형식에 안 맞을 때."""


def parse(vector: str) -> dict:
    """'CVSS:3.1/AV:N/...' → {'AV': 'N', ...}. 틀리면 BadVector."""
    text = (vector or "").strip()
    if not text:
        raise BadVector("벡터가 비어 있습니다")
    parts = text.split("/")
    if not parts[0].upper().startswith("CVSS:3"):
        raise BadVector("CVSS:3.0 또는 CVSS:3.1 로 시작해야 합니다")
    got = {}
    for part in parts[1:]:
        m = _PART.match(part.strip().upper())
        if not m:
            raise BadVector(f"알 수 없는 조각입니다: {part}")
        key, val = m.group(1), m.group(2)
        if key not in CHOICES:
            raise BadVector(f"모르는 지표입니다: {key}")
        if val not in CHOICES[key]:
            raise BadVector(f"{key} 에는 {'·'.join(CHOICES[key])} 중 하나를 씁니다 (받은 값: {val})")
        got[key] = val
    missing = [k for k in ORDER if k not in got]
    if missing:
        raise BadVector(f"빠진 지표가 있습니다: {', '.join(missing)}")
    return got


def build(values: dict) -> str:
    """{'AV': 'N', ...} → 'CVSS:3.1/AV:N/...'. 빠진 것이 있으면 BadVector."""
    out = [VERSION]
    for key in ORDER:
        val = (values.get(key) or "").strip().upper()
        if val not in CHOICES[key]:
            raise BadVector(f"{key} 를 골라 주세요")
        out.append(f"{key}:{val}")
    return "/".join(out)


def _roundup(x: float) -> float:
    """명세의 Roundup — 소수 첫째 자리로 올림. 부동소수 오차를 피하려고 정수로 바꿔 센다."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def score(vector) -> float:
    """기본 점수. 문자열이든 {'AV': 'N', ...} 이든 받는다."""
    v = parse(vector) if isinstance(vector, str) else vector
    for key in ORDER:
        if v.get(key) not in CHOICES[key]:
            raise BadVector(f"{key} 를 골라 주세요")

    iss = 1 - ((1 - W["C"][v["C"]]) * (1 - W["I"][v["I"]]) * (1 - W["A"][v["A"]]))
    changed = v["S"] == "C"
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploit = 8.22 * W["AV"][v["AV"]] * W["AC"][v["AC"]] * PR_W[v["S"]][v["PR"]] * W["UI"][v["UI"]]
    raw = (impact + exploit) * (1.08 if changed else 1.0)
    return _roundup(min(raw, 10.0))


def band(value: float):
    """점수 → (대시보드 심각도, 보여 줄 이름). 9.8 → ('critical', 'Critical')"""
    for low, sev, label in BANDS:
        if value >= low:
            return sev, label
    return "info", "None"


def rate(vector) -> dict:
    """벡터 하나를 화면에 쓸 모양으로. 틀린 벡터면 BadVector 가 그대로 올라간다."""
    v = parse(vector) if isinstance(vector, str) else dict(vector)
    s = score(v)
    sev, label = band(s)
    return {"vector": build(v), "values": v, "score": s, "severity": sev, "label": label,
            # 노션 '웹 서비스 취약점 목록' 의 CVSS 속성은 Low·Medium·High 세 가지뿐이다
            "notion": {"critical": "High", "high": "High", "medium": "Medium",
                       "low": "Low", "info": "Low"}[sev],
            # 노션 본문의 '영향도(CVSS 3.1)' 칸 모양
            "impact_text": f"{label}({s})"}
