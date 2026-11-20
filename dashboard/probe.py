"""지점 점검 모듈이 같이 쓰는 도구: 값 넣어 보내기, 응답에 어떻게 돌아왔는지 판정."""
import json
import re
import uuid
from urllib.parse import quote, urlencode

from . import core

CONTEXT_LABEL = {"html": "본문", "attribute": "태그 속성", "script": "스크립트 블록"}


def marker() -> str:
    """응답에서 찾기 쉬운 고유 표식. 요청마다 새로 만든다."""
    return "vcd" + uuid.uuid4().hex[:8]


def send(point, value: str):
    """point.param 자리에 value 를 넣어 보낸다. 같은 요청의 다른 파라미터는 발견 당시 값으로 채운다."""
    if point.place == "header":
        return core.fetch(point.url, headers={point.param: value})
    if point.place == "path":
        # /lectures/{id} 의 {id} 자리에 넣는다. 다른 경로 변수는 1 로 채운다
        url = re.sub(r"\{[^}/]+\}", "1", point.url.replace("{" + point.param + "}", quote(value, safe="")))
        return core.fetch(url)
    fields = {**point.fields, point.param: value}
    if point.place == "json":
        return core.fetch(point.url, method=point.method if point.method != "GET" else "POST",
                          raw_body=json.dumps(fields, ensure_ascii=False).encode())
    if point.place == "form" and point.method == "POST":
        return core.fetch(point.url, method="POST", data=fields)
    return core.fetch(point.url + "?" + urlencode(fields))


def request_line(point, value: str) -> str:
    """근거에 남길 요청 한 줄. 다른 파라미터 값은 적지 않는다."""
    if point.place == "path":
        return f"GET {point.url.replace('{' + point.param + '}', value)}"
    if point.place == "header":
        return f"{point.method} {point.url}  [헤더 {point.param}: {value}]"
    if point.place == "json":
        return f"{point.method} {point.url}  [JSON {point.param}={value}]"
    if point.place == "form" and point.method == "POST":
        return f"POST {point.url}  [본문 {point.param}={value}]"
    return f"GET {point.url}?{point.param}={value}"


def _context(body: str, i: int) -> str:
    before = body[:i]
    if before.lower().rfind("<script") > before.lower().rfind("</script"):
        return "script"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html"


def _excerpt(body: str, i: int, n: int, pad: int = 40) -> str:
    return body[max(0, i - pad): i + n + pad].replace("\n", " ").strip()


def encoded_echo(body: str, sent: str):
    """보낸 값이 **퍼센트 인코딩된 채로만** 돌아왔는가 → 그 자리의 발췌, 아니면 None.

    경로 변수를 풀지 않고 응답 데이터에 그대로 담는 화면이 이렇다(Next.js 라우터 묶음
    `self.__next_f.push([1,"…params…"])` 가 그렇다). `"` 는 `%22`, `<` 는 `%3C` 로 남으므로
    문자열을 닫거나 태그를 만들 수 없다 — 스크립트 블록 안에 돌아와도 실행되지 않는다.
    11-20 관리자 웹 경로 변수 4개(`/users/{userId}` 등)를 브라우저로 확인한 결과다.
    """
    enc = quote(sent, safe="")
    if enc == sent or sent in body:  # 특수문자가 없는 값, 또는 날것으로 돌아온 값은 여기서 볼 게 없다
        return None
    i = body.find(enc)
    return _excerpt(body, i, len(enc)) if i >= 0 else None


def judge_reflection(body: str, token: str, sent: str):
    """보낸 값(sent, token 포함)이 응답에 어떻게 돌아왔는지 본다 → (verdict, 위치, 발췌).

    그대로 돌아옴                  → vuln      (특수문자가 걸러지지 않음 — 후보)
    표식은 있는데 특수문자가 바뀜·빠짐 → potential (필터 있음 — 다른 패턴으로 더 볼 곳)
    표식 자체가 없음               → safe      (반사되지 않음)
    """
    i = body.find(sent)
    if i >= 0:
        return "vuln", _context(body, i), _excerpt(body, i, len(sent))
    j = body.find(token)
    if j >= 0:
        return "potential", _context(body, j), _excerpt(body, j, len(token) + 12)
    return "safe", "", ""


# ── 단계 점검(11-20 사용자 결정) ────────────────────────────────
# 지점마다 취약점 종류별로 ① 받는 구간인지 먼저 보고(후보 고르기), 후보로 남은 지점에만
# ② 기본 페이로드 → ③ 심화 페이로드 → ④ 우회 페이로드 순서로 넣는다. 하나라도 확인되면 멈춘다.
# 받는 구간이 아니면 거기서 끝내 요청을 아낀다.

STAGES = ("screen", "basic", "deep", "bypass")
STAGE_LABEL = {"screen": "① 받는 구간", "basic": "② 기본", "deep": "③ 심화", "bypass": "④ 우회"}


class Ladder:
    """한 지점의 단계 점검 기록. 모듈은 단계마다 try_payloads 를 부르고 끝에 check() 로 판정을 만든다."""

    def __init__(self, point):
        self.point = point
        self.lines = []
        self.verdict, self.response, self.title, self.stage = "safe", None, "", ""
        self.encoded = []  # 인코딩된 채로만 돌아온 자리 [(단계, 설명, 발췌)]

    def note(self, stage, text):
        self.lines.append(f"{STAGE_LABEL[stage]} {text}")

    def hit(self, stage, response, title, note=""):
        self.verdict, self.response, self.title, self.stage = "vuln", response, title, stage
        if note:
            self.note(stage, note)

    def maybe(self, stage, response, note):
        if self.verdict == "safe":
            self.verdict, self.response, self.stage = "potential", response, stage
        self.note(stage, note)

    def encoded_only(self, stage="bypass"):
        """인코딩된 채로만 돌아왔으면 근거에 적고 True — 깨뜨릴 수 없으니 안전으로 둔다."""
        if self.verdict != "safe" or not self.encoded:
            return False
        kind, excerpt = self.encoded[-1][1:]
        self.note(stage, f"넣은 값이 퍼센트 인코딩된 채로만 돌아옴({kind}) — `\"` 는 %22, `<` 는 %3C 로 남아 "
                         f"문자열·태그를 깨뜨릴 수 없음: …{excerpt}…")
        self.note(stage, "돌아오는 자리가 스크립트 블록이어도 실행되지 않는 모양이다 — 안전")
        return True

    @property
    def done(self):
        return self.verdict == "vuln"

    def try_payloads(self, stage, payloads, confirm):
        """payloads: [(값, 설명)]. confirm(응답, 값) 이 (제목, 메모) 를 돌려주면 확인된 것."""
        for value, kind in payloads:
            r = send(self.point, value)
            self.note(stage, f"{kind}: {request_line(self.point, value)} → {r.status} · {len(r.body)}B")
            got = confirm(r, value)
            if got:
                self.hit(stage, r, got[0], got[1])
                return True
            excerpt = encoded_echo(r.body, value)
            if excerpt:
                self.encoded.append((stage, kind, excerpt))
        return False
