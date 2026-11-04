"""사전의 입력을 지점마다 하나씩 넣어 보고, 응답으로 걸러지는지·오류가 새는지 본다.

'입력값 반사 확인'은 특수문자 한 묶음만 보내지만, 이 모듈은 **사전에 적힌 입력을 차례로** 보낸다.
SecLists 의 Fuzzing 목록을 그대로 걸어도 된다.

보는 것은 두 가지다.
  1. 넣은 값이 응답에 그대로 돌아오는가 (걸러지지 않음)
  2. DB·프레임워크 오류 메시지가 응답에 새는가 (처리되지 않은 입력)
둘 다 '여기를 더 보라'는 표시지, 터졌다는 뜻이 아니다.
"""
import re

from dashboard import probe
from dashboard.core import Check

META = {
    "id": "payload_probe",
    "name": "사전으로 입력값 넣어 보기",
    "category": "입력 검증",
    "kind": "active",
    "stage": "probe",
    "severity": "medium",
    "attack": [
        {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
        {"tactic": "TA0002", "technique": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
    ],
    "description": "사전의 입력을 지점마다 차례로 넣고, 그대로 돌아오는지·오류가 새는지 봅니다. {T} 는 그 요청의 표식으로 바뀝니다.",
    "needs": [
        {"kind": "env", "name": "DASH_WORDLISTS", "required": False,
         "why": "저장소에 든 씨앗 사전만으로는 찾는 범위가 좁습니다. SecLists 를 붙이면 고르는 칸에 함께 뜹니다",
         "how": "SecLists 를 받아 대시보드를 띄우기 전에 DASH_WORDLISTS 에 그 폴더를 넣습니다 (wordlists/README.md)"},
    ],
    "params": [
        {"name": "wordlist", "label": "사전", "type": "wordlist", "default": "payload-reflect.txt"},
        {"name": "limit", "label": "지점마다 몇 개", "type": "int", "default": "6",
         "help": "지점 수 × 이 수만큼 요청이 나갑니다. 지점 10개 × 6 = 60번."},
        {"name": "methods", "label": "보낼 메서드", "default": "GET",
         "help": "POST 를 넣으면 폼을 실제로 제출합니다 — 테스트 계정·테스트 행에서만."},
    ],
}

# 응답에 이런 말이 보이면 입력이 그대로 엔진까지 간 것이다.
ERROR_SIGNS = [
    (re.compile(r"ORA-\d{5}"), "Oracle"),
    (re.compile(r"SQLSyntaxErrorException|BadSqlGrammarException"), "JDBC/Spring"),
    (re.compile(r"You have an error in your SQL syntax"), "MySQL"),
    (re.compile(r"org\.postgresql\.util\.PSQLException"), "PostgreSQL"),
    (re.compile(r"SQLITE_ERROR|sqlite3\.OperationalError"), "SQLite"),
    (re.compile(r"java\.lang\.\w+(?:Exception|Error)"), "Java 예외"),
    (re.compile(r"Traceback \(most recent call last\)"), "Python 예외"),
]


# 이 글자들이 그대로 돌아와야 '안 걸러졌다'고 말할 수 있다.
# 특수문자가 없는 입력(표식만)이 돌아온 것은 '여기가 반사된다'는 뜻일 뿐이다.
SPECIAL = set("<>\"'&;`\\(){}")


def _error_sign(body):
    for pattern, name in ERROR_SIGNS:
        m = pattern.search(body)
        if m:
            return name, m.group(0)
    return None, ""


def run(target, points, params):
    from dashboard.wordlists import load
    payloads, _ = load(params.get("wordlist", ""), limit=int(params.get("limit") or 6))
    allowed = {m.strip().upper() for m in params.get("methods", "GET").split(",") if m.strip()}
    if not payloads:
        raise ValueError("사전이 비어 있습니다")

    out = []
    for point in points:
        if point.method not in allowed:
            continue
        verdict, lines, title, best = "safe", [], "", None
        for payload in payloads:
            token = probe.marker()
            sent = payload.replace("{T}", token)
            if token not in sent:          # {T} 가 없는 사전이면 앞에 붙여 되돌아온 자리를 찾는다
                sent = token + sent
            r = probe.send(point, sent)
            seen, where, excerpt = probe.judge_reflection(r.body, token, sent)
            engine, sign = _error_sign(r.body)

            if engine:
                verdict, title = "vuln", f"오류 메시지가 새어 나옴({engine})"
                lines = [f"{probe.request_line(point, sent)} → {r.status}", f"응답에 {engine} 오류: {sign}"]
                best = r
                break
            ctype = (r.header("Content-Type") or "-").split(";")[0]
            risky = SPECIAL & set(sent)
            if seen == "vuln" and risky and verdict != "vuln":
                verdict, title = "vuln", f"입력값이 그대로 반사됨({probe.CONTEXT_LABEL[where]})"
                lines = [f"{probe.request_line(point, sent)} → {r.status} [{ctype}]",
                         f"걸러지지 않은 글자: {' '.join(sorted(risky))}",
                         f"반사 위치: {probe.CONTEXT_LABEL[where]}", f"…{excerpt}…"]
                if "html" not in ctype:
                    lines.append("응답이 HTML 이 아닙니다 — 브라우저가 이 자리를 태그로 읽는지 직접 확인하세요.")
                best = r
            elif seen != "safe" and verdict == "safe":
                # 특수문자 없이 돌아왔거나(반사되는 자리), 돌아왔는데 바뀐 경우(필터 있음)
                verdict = "potential"
                lines = [f"{probe.request_line(point, sent)} → {r.status}",
                         "표식이 돌아오지만 특수문자가 그대로는 아님(필터 있음 / 반사되는 자리)"]
                best = r

        if not lines:
            lines = [f"사전 {len(payloads)}개를 넣었지만 응답에 표식이 없었습니다"]
        out.append(Check(
            point=point, verdict=verdict, evidence="\n".join(lines), title=title, response=best,
            recommendation=("출력 위치에 맞게 인코딩하고(본문은 HTML 엔티티, 속성은 따옴표 포함, 스크립트 안은 JS 이스케이프), "
                            "DB 질의는 바인드 변수로 넘깁니다. 운영에서는 예외 상세를 응답에 싣지 않습니다.")))
    return out
