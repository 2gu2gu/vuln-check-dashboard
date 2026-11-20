"""지점 점검 모듈이 같이 쓰는 도구: 값 넣어 보내기, 응답에 어떻게 돌아왔는지 판정."""
import json
import re
import uuid
from urllib.parse import quote, urlencode, urlsplit

from . import core

CONTEXT_LABEL = {"html": "본문", "attribute": "태그 속성", "script": "스크립트 블록"}

# 경로 틀의 {변수} 자리에 넣을 진짜 번호. 1 로 채우면 대개 404 라 점검이 ① 에서 멈춘다.
# 11-21 실측: /backend/lectures/{lid}/qna/{qnaid} 를 1/1 로 부르면 404 인데, 한 단계 위 목록
# /backend/lectures/103/qna 를 읽으면 qid 460 이 나오고 그 글은 인증 없이 열린다(비밀글 노출).
# 도구가 그걸 못 보고 지나간 건 번호를 못 찾아서였다.
ID_IN_JSON = re.compile(r'"[A-Za-z_]*(?:id|Id|ID|no|No|seq|Seq|num|Num)"\s*:\s*(\d{1,12})')
ID_IN_PATH = re.compile(r"/(\d{1,12})(?=[/\"'\s]|$)")
FALLBACK_IDS = ("1", "2", "3", "103", "123")
MAX_TRY = 6


def marker() -> str:
    """응답에서 찾기 쉬운 고유 표식. 요청마다 새로 만든다."""
    return "vcd" + uuid.uuid4().hex[:8]


def _ids_from(body: str, limit=MAX_TRY):
    """응답에서 번호 후보를 뽑는다 — JSON 의 *id 키가 먼저, 없으면 경로 안의 숫자."""
    out = []
    for m in list(ID_IN_JSON.finditer(body))[:40] + list(ID_IN_PATH.finditer(body))[:40]:
        v = m.group(1)
        if v not in out and v != "0":
            out.append(v)
        if len(out) >= limit:
            break
    return out


def path_ids(url: str, skip: str = ""):
    """경로 틀의 {변수} 마다 **실제로 응답하는 번호** 를 찾는다 → {변수: 값}.

    왼쪽부터 한 칸씩 채운다. 변수 앞까지의 경로가 그 변수의 '목록 주소' 다
    (`/lectures/{lid}/qna/{qnaid}` 의 {qnaid} 라면 `/lectures/103/qna`).
    목록을 읽어 번호를 거두고, 그 번호로 한 칸 더 간 주소가 2xx 면 그것을 쓴다.
    skip 에 적은 변수는 모듈이 직접 넣으므로 비워 둔다.

    한 실행 안에서는 같은 주소를 두 번 찾지 않는다(core.run_cache).
    """
    # 고의 열쇠·값은 그대로 DB 에 들어간다 — 글자만 쓴다(11-21: 튜플 열쇠로 실행 하나를 통째로 날렸다)
    cache = core.run_cache()
    key = f"path_ids	{url}	{skip}"
    if key in cache:
        try:
            return json.loads(cache[key])
        except (TypeError, ValueError):
            pass
    found, prefix = {}, ""
    for seg in urlsplit(url).path.strip("/").split("/"):
        if not (seg.startswith("{") and seg.endswith("}")):
            prefix += "/" + seg
            continue
        name = seg[1:-1]
        if name == skip:
            found[name] = ""
            prefix += "/{" + name + "}"
            continue
        base = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}{prefix}"
        guesses = []
        try:
            lst = core.fetch(base)
            if 200 <= lst.status < 300:
                guesses = _ids_from(lst.body)
        except OSError:
            pass
        for g in guesses + [v for v in FALLBACK_IDS if v not in guesses]:
            try:
                r = core.fetch(base + "/" + g)
            except OSError:
                continue
            if 200 <= r.status < 300:
                found[name] = g
                break
        else:
            found[name] = "1"
        prefix += "/" + found[name]
    cache[key] = json.dumps(found, ensure_ascii=False)
    return found


def fill_path(url: str, param: str, value: str) -> str:
    """경로 틀에서 param 자리에 value 를 넣고, 나머지 변수는 찾아낸 번호로 채운다."""
    ids = path_ids(url, skip=param)
    out = url.replace("{" + param + "}", quote(value, safe=""))
    for name, got in ids.items():
        out = out.replace("{" + name + "}", got or "1")
    return re.sub(r"\{[^}/]+\}", "1", out)


def send(point, value: str):
    """point.param 자리에 value 를 넣어 보낸다. 같은 요청의 다른 파라미터는 발견 당시 값으로 채운다."""
    if point.place == "header":
        return core.fetch(point.url, headers={point.param: value})
    if point.place == "path":
        # /lectures/{lid}/qna/{qnaid} 의 {qnaid} 자리에 넣는다. 다른 변수는 **실제로 응답하는 번호**
        # 를 한 단계 위 목록에서 거둬 채운다 — 1 로 채우면 대개 404 라 점검이 ① 에서 끝난다
        return core.fetch(fill_path(point.url, point.param, value))
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

def app_shell(target):
    """대상 첫 화면을 인증 없이 한 번 읽어 둔다 → 본문, 없으면 None.

    React·Vue·Next 같은 앱은 **어느 주소를 불러도 같은 index.html** 을 돌려준다. 그 본문과 글자
    하나까지 같은 응답이 오면 그 주소는 '보호된 화면' 도 '그 번호의 자원' 도 아니라 앱 껍데기다.
    권한은 뒤쪽 API 가 보는데 그건 이 주소가 아니다.
    11-21 실측: 사용자 웹의 /mypage·/instructor·/mypage/buy/history/1 이 전부 같은 564바이트였고,
    그걸 모르는 채로 인증·인가가 취약 6, IDOR 이 취약 7 을 적었다. 둘 다 거짓 양성이었다.
    """
    try:
        r = core.fetch(core.join(target.url, "/"), auth=False)
    except OSError:
        return None
    return r.body if 200 <= r.status < 300 and r.body else None


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
