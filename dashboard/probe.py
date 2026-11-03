"""지점 점검 모듈이 같이 쓰는 도구: 값 넣어 보내기, 응답에 어떻게 돌아왔는지 판정."""
import uuid
from urllib.parse import urlencode

from . import core

CONTEXT_LABEL = {"html": "본문", "attribute": "태그 속성", "script": "스크립트 블록"}


def marker() -> str:
    """응답에서 찾기 쉬운 고유 표식. 요청마다 새로 만든다."""
    return "vcd" + uuid.uuid4().hex[:8]


def send(point, value: str):
    """point.param 자리에 value 를 넣어 보낸다. 같은 요청의 다른 파라미터는 발견 당시 값으로 채운다."""
    fields = {**point.fields, point.param: value}
    if point.place == "form" and point.method == "POST":
        return core.fetch(point.url, method="POST", data=fields)
    return core.fetch(point.url + "?" + urlencode(fields))


def request_line(point, value: str) -> str:
    """근거에 남길 요청 한 줄. 다른 파라미터 값은 적지 않는다."""
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
