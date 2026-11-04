"""모듈을 어떤 기준으로 묶어 보여 줄지.

화면 위 탭에서 고른다. 기본은 **단계** — 그게 쓰는 순서이기 때문이다.
표면 모으고 → 찔러 보고 → 보고. 처음 쓰는 팀원이 위에서 아래로 따라가면 된다.

    단계     쓰는 순서대로            (기본)
    전술     ATT&CK — 발표·보고서 쓸 때
    분야     "SQL 주입 도구 어디 있지" 하고 찾을 때
    취약점    팀원이 취약점별로 모듈을 만들어 가므로

**취약점 어휘는 팀 노션 '웹 서비스 취약점 목록' 의 선택지를 그대로 쓴다.**
정보노출·AUTH·XSS·FILE·SQL. 그래야 모듈·노션 취약점 항목·CVSS 가 같은 말로 묶인다.
그 어휘로 안 맞는 모듈(표면 수집 등)은 '기타' 다 — 억지로 끼워 맞추지 않는다.
"""
from .attack import TACTIC_NAME, TACTIC_ORDER
from .registry import STAGE_LABEL

# 노션 '웹 서비스 취약점 목록' 의 '취약점 유형' 선택지 + 안 맞는 것을 담을 '기타'
VULN_TYPES = ["정보노출", "AUTH", "XSS", "FILE", "SQL", "기타"]
VULN_HINT = {
    "정보노출": "응답에 있으면 안 될 것이 그대로 드러나는 것 — 버전·세션·내부 경로",
    "AUTH": "인증·인가를 지나치는 것",
    "XSS": "넣은 값이 브라우저에서 코드로 읽히는 것",
    "FILE": "있으면 안 될 파일을 읽거나 올리는 것 — 경로 조작 포함",
    "SQL": "입력이 질의문으로 섞여 들어가는 것",
    "기타": "취약점을 찾는 모듈이 아니거나 위 어휘로 안 맞는 것",
}

# 화면 위 탭. 순서가 탭 순서다.
WAYS = [
    ("stage", "단계", "쓰는 순서 — 표면 모으고 → 찔러 보고 → 보고"),
    ("tactic", "전술", "ATT&CK 전술. 발표·보고서에 쓴다"),
    ("category", "분야", "하는 일의 갈래"),
    ("vuln", "취약점", "노션 '웹 서비스 취약점 목록' 과 같은 어휘"),
]
DEFAULT_WAY = "stage"
WAY_LABEL = {k: label for k, label, _ in WAYS}


def _stage_key(m):
    return [(m.stage, STAGE_LABEL[m.stage])]


def _tactic_key(m):
    seen = []
    for a in m.attack:
        tac = a.get("tactic")
        if tac and tac not in [k for k, _ in seen]:
            seen.append((tac, TACTIC_NAME.get(tac, tac)))
    return seen or [("", "전술 없음")]


def _category_key(m):
    return [(m.category, m.category)]


def _vuln_key(m):
    v = getattr(m, "vuln", "") or "기타"
    return [(v, v)]


KEYS = {"stage": _stage_key, "tactic": _tactic_key, "category": _category_key, "vuln": _vuln_key}

# 묶음 순서. 단계는 쓰는 순서, 전술은 공격 진행 순서, 나머지는 큰 묶음부터.
ORDER = {
    "stage": lambda key, n: list(STAGE_LABEL).index(key) if key in STAGE_LABEL else 99,
    "tactic": lambda key, n: TACTIC_ORDER.get(key, 99),
    "vuln": lambda key, n: VULN_TYPES.index(key) if key in VULN_TYPES else 98,
}


def group(modules, way=DEFAULT_WAY):
    """[{key, label, hint, modules}] — 고른 기준으로 묶는다.

    한 모듈이 전술을 여럿 달고 있으면 **여러 묶음에 들어간다.** 그게 사실이기 때문이다 —
    숨기면 '그 전술에는 쓸 모듈이 없다'로 읽힌다.
    """
    way = way if way in KEYS else DEFAULT_WAY
    key_of = KEYS[way]
    buckets = {}
    for m in modules:
        for key, label in key_of(m):
            buckets.setdefault(key, {"key": key, "label": label, "modules": []})["modules"].append(m)

    order = ORDER.get(way)
    rows = sorted(buckets.values(),
                  key=(lambda b: (order(b["key"], len(b["modules"])), b["label"])) if order
                  else (lambda b: (-len(b["modules"]), b["label"])))
    for b in rows:
        b["modules"].sort(key=lambda m: (bool(m.project), m.name))
        b["hint"] = VULN_HINT.get(b["key"], "") if way == "vuln" else ""
    return rows


def empty_groups(way, rows):
    """고른 기준에서 **비어 있는 묶음**. 없는 것을 없다고 말해 주려고 쓴다.

    취약점 기준에서 'XSS 칸이 비었다'는 '아직 XSS 모듈이 없다'는 뜻이고,
    그건 팀원이 다음에 만들 것을 고르는 데 쓸모 있는 정보다.
    """
    if way != "vuln":
        return []
    have = {b["key"] for b in rows}
    return [v for v in VULN_TYPES if v not in have and v != "기타"]
