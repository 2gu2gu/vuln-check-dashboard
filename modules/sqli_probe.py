"""고른 지점마다 SQL 주입을 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

모듈은 취약점별로 수집한 지점에 '전부 때리는' 구조다(사용자 결정 11-20). 지점마다 먼저 이 입력이
질의까지 가는 구간인지 보고, 후보로 남은 지점에만 페이로드를 늘려 넣는다. 확인되면 그 단계에서 멈춘다.
표를 읽어 내는 일은 하지 않는다 — 그것은 확인한 뒤 쓰는 심화 모듈(강의 목록 SQL 주입)의 몫이다.

  ① 받는 구간  작은따옴표 하나에 응답이 달라지는가(오류 문구·상태·길이). 같으면 후보 아님 → 안전으로 끝
  ② 기본       참·거짓 조건(AND 'q'='q / 'q'='z, 숫자면 AND 1=1 / 1=2) — 참은 원래와 같고 거짓만 달라야 확인
  ③ 심화       주석으로 뒤를 끊는 모양(--, #), LIKE 검색 자리, DB 별 상수 비교
  ④ 우회       공백 대신 주석(/**/), 대소문자 섞기, 이중 인코딩된 따옴표
데이터를 바꾸는 값(OR 1=1, UPDATE·DROP 등)은 보내지 않는다. AND 조건만 쓴다.
"""
import re

from dashboard import probe
from dashboard.core import Check

META = {
    "id": "sqli_probe",
    "name": "SQL 주입 점검",
    "category": "SQL 주입",
    "kisa": ["SI"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "SQL",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "kind": "active",
    "stage": "probe",
    "severity": "high",
    "attack": [{"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"}],
    "description": "고른 지점마다 **① 받는 구간**(따옴표 하나에 응답이 달라지는지)을 먼저 보고, 후보에만 "
                   "② 기본(참·거짓 조건) → ③ 심화(주석·LIKE·DB 상수) → ④ 우회(/**/·대소문자·인코딩) 순서로 넣습니다. "
                   "표를 읽어 내지는 않습니다 — 취약이 나오면 심화 모듈로 넘어갑니다.",
    "params": [
        {"name": "methods", "need": "required", "label": "보낼 메서드", "default": "GET",
         "help": "POST 를 넣으면 폼을 실제로 제출합니다 — 테스트 계정·테스트 행에서만"},
    ],
}

ERROR_SIGNS = [
    (re.compile(r"ORA-\d{5}"), "Oracle"),
    (re.compile(r"SQLSyntaxErrorException|BadSqlGrammarException"), "JDBC/Spring"),
    (re.compile(r"You have an error in your SQL syntax"), "MySQL"),
    (re.compile(r"org\.postgresql\.util\.PSQLException"), "PostgreSQL"),
    (re.compile(r"SQLITE_ERROR|sqlite3\.OperationalError|unrecognized token"), "SQLite"),
    (re.compile(r"Unclosed quotation mark|SqlException"), "SQL Server"),
]
_REC = ("값을 문자열로 이어 붙이지 말고 바인드 변수(PreparedStatement, ORM 파라미터)로 넘깁니다. "
        "정렬 기준·컬럼명처럼 바인드할 수 없는 자리는 허용 목록에서 고릅니다. DB 오류 문구는 응답에 내보내지 않습니다.")


def _same(a, b):
    tol = max(20, int(len(a.body) * 0.02))
    return a.status == b.status and abs(len(a.body) - len(b.body)) <= tol


def _engine(body):
    return next((name for rx, name in ERROR_SIGNS if rx.search(body)), "")


def stages(v):
    """단계별 (참, 거짓, 설명) 짝. 값이 숫자면 숫자 자리를 먼저 본다."""
    num = v.isdigit()
    return {
        "basic": ([(f"{v} AND 1=1", f"{v} AND 1=2", "숫자 자리")] if num else [])
                 + [(f"{v}' AND 'q'='q", f"{v}' AND 'q'='z", "문자열 자리")],
        "deep": [(f"{v}' AND 1=1-- ", f"{v}' AND 1=2-- ", "주석으로 끊기(--)"),
                 (f"{v}' AND 1=1#", f"{v}' AND 1=2#", "주석으로 끊기(#)"),
                 (f"{v}%' AND 'q'='q' AND '%'='", f"{v}%' AND 'q'='z' AND '%'='", "LIKE 검색 자리"),
                 (f"{v}' AND (SELECT 1 FROM DUAL)=1 AND 'q'='q", f"{v}' AND (SELECT 1 FROM DUAL)=2 AND 'q'='q", "Oracle 상수")],
        "bypass": [(f"{v}'/**/AND/**/'q'='q", f"{v}'/**/AND/**/'q'='z", "공백 대신 주석"),
                   (f"{v}' aNd 'q'='q", f"{v}' aNd 'q'='z", "대소문자 섞기"),
                   (f"{v}%27 AND %27q%27=%27q", f"{v}%27 AND %27q%27=%27z", "따옴표 이중 인코딩")],
    }


def run(target, points, params):
    allowed = {m.strip().upper() for m in params.get("methods", "GET").split(",") if m.strip()}
    out = []
    for p in points:
        if p.method not in allowed:
            continue
        lad = probe.Ladder(p)
        v = p.sample or ("1" if p.param.lower() in ("id", "page", "size", "no") else "a")
        base = probe.send(p, v)
        lad.note("screen", f"원래 값: {probe.request_line(p, v)} → {base.status} · {len(base.body)}B")

        # ① 받는 구간 — 따옴표 하나에 응답이 그대로면 질의로 가지 않는 자리로 본다
        q = probe.send(p, v + "'")
        lad.note("screen", f"따옴표: {probe.request_line(p, v + chr(39))} → {q.status} · {len(q.body)}B")
        engine = _engine(q.body)
        if engine:
            lad.hit("screen", q, f"SQL 주입 — 오류 기반({engine})", f"DB 오류 메시지가 응답에 보임({engine})")
        elif _same(q, base):
            lad.note("screen", "따옴표에도 응답이 같음 — 받는 구간이 아님(후보 제외)")
        else:
            lad.note("screen", "따옴표에 응답이 달라짐 — 후보")
            for stage, pairs in stages(v).items():
                for yes, no, kind in pairs:
                    ry, rn = probe.send(p, yes), probe.send(p, no)
                    lad.note(stage, f"{kind}: 참 {ry.status}·{len(ry.body)}B / 거짓 {rn.status}·{len(rn.body)}B")
                    if _same(ry, base) and not _same(rn, ry):
                        lad.hit(stage, ry, f"SQL 주입 — 참·거짓 기반({kind})",
                                "참 조건은 원래 응답과 같고 거짓 조건만 달라짐")
                        break
                    eng = _engine(rn.body) or _engine(ry.body)
                    if eng:
                        lad.hit(stage, rn, f"SQL 주입 — 오류 기반({eng}, {kind})", f"DB 오류 메시지({eng})")
                        break
                if lad.done:
                    break
            if not lad.done and q.status >= 500 and base.status < 500:
                lad.maybe("bypass", q, "따옴표에 서버 오류(500)만 남고 조건 차이는 못 봄 — 다른 패턴으로 더 볼 곳")
        out.append(Check(point=p, verdict=lad.verdict, evidence="\n".join(lad.lines), response=lad.response or base,
                         title=lad.title, recommendation=_REC))
    return out
