"""고른 주소에 파일을 올려 검증이 있는지 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

노션 '웹 서비스 취약점 목록' 의 FILE 묶음에 업로드 건이 셋 있다(강의 생성 업로드 검증 미상,
과제 제출 확장자 검증 우회, 과제 업로드 경로 조작 쉘파일 업로드 RCE). 전부 **무엇을 받아 주는가** 로
드러나고, 그건 올려 보면 알 수 있다.

  ① 받는 구간  무해한 .txt 를 올린다. 2xx 가 아니면 업로드 자리가 아니거나 다른 칸이 더 필요하다.
               **여기서 걸리면 판정은 '확인 못 함' 이다 — 안전이 아니다**(11-21 사용자 지적: 145곳이
               전부 '안전' 으로 나왔는데 사람은 같은 서비스에서 쉘 파일을 올렸다. 때려 보지도 못한
               자리를 안전이라고 적으면 판 전체가 거짓말이 된다)
               **2xx 라고 다 받는 자리는 아니다** — Next.js 같은 앱은 POST 에도 화면(HTML)을 그대로
               돌려준다. 화면이 오거나, 파일을 빼고 보내도 같은 것이 오면 받는 자리가 아니다
               (11-21 실측: 관리자 웹 화면 라우트 11곳이 이것 때문에 전부 '확장자 검증 없음' 으로 잘못 잡혔다)
  ② 기본       그냥 .jsp·.php·.html 을 올린다 — 받아 주면 확장자 검증이 없다
  ③ 심화       이름에 경로를 섞는다(`../`, 역슬래시, 절대 경로) — 받아 주면 올릴 자리를 고를 수 있다
  ④ 우회       검증이 있을 때 지나가는 모양: 겹친 확장자(.jsp.txt), 대소문자(.JsP), 널바이트, 세미콜론,
               Content-Type 만 바꾸기

판정: 쉘로 돌 수 있는 확장자나 경로 섞은 이름을 받아 주면 취약, 2xx 지만 돌려준 이름·경로를 알 수 없으면
잠재(올라간 파일을 직접 찾아봐야 한다), .txt 는 받는데 나머지를 다 막으면 안전,
**① 에서 못 넘어가면 확인 못 함**(설정을 고쳐 다시 돌릴 곳이다).

경로 틀(`/backend/lectures/{lid}/assignments/file`)은 `{lid}` 를 **실제로 응답하는 번호**로 채워 보낸다.
그대로 보내면 404 라서 진짜 업로드 자리가 ① 에서 떨어진다 — 11-21 에 그래서 과제 제출 업로드를 놓쳤다.

**파일이 올라가 남는다.** 올리는 내용은 표식 한 줄뿐이고 명령을 돌리는 코드가 아니다 — 받아 주는지만
보는 점검이다. 끝난 뒤 남은 파일은 직접 지운다(근거에 적힌 표식으로 찾는다).
"""
import re
import uuid

from dashboard import core, probe
from dashboard.core import Check

META = {
    "id": "upload_probe",
    "name": "파일 업로드 검증 점검",
    "category": "입력 검증",
    "kisa": ["FU", "FD"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "FILE",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "kind": "active",
    "stage": "probe",
    "unit": "endpoint",
    "severity": "critical",
    "attack": [{"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
               {"tactic": "TA0002", "technique": "T1059", "name": "Command and Scripting Interpreter"}],
    "description": "고른 **주소마다** 파일을 올려 ② 그냥 .jsp·.php 를 받아 주는지, ③ 이름에 섞은 경로(`../`·역슬래시)를 "
                   "따르는지, ④ 겹친 확장자·대소문자·널바이트로 검증을 지나가는지 봅니다. "
                   "**파일이 올라가 남습니다 — 끝난 뒤 직접 지우세요.** 표식으로 찾을 수 있게 근거에 적어 둡니다.",
    "needs": [
        {"kind": "account", "required": False,
         "why": "업로드는 보통 로그인해야 열리고, 올라간 파일은 그 계정 이름으로 남습니다",
         "how": "대상 탭의 **2. 인증** 에 테스트 계정 토큰을 넣습니다"},
    ],
    "params": [
        {"name": "field", "need": "required", "label": "파일 칸 이름", "default": "file",
         "help": "HAR 에서 본 multipart 의 파일 칸 이름입니다(file·upload·attachment 등)."},
        {"name": "extra", "need": "optional", "label": "같이 보낼 값(이름=값, 줄마다 하나)", "type": "textarea", "default": "",
         "placeholder": "title=점검용\nlectureId=103",
         "help": "업로드 폼이 다른 칸도 요구하면 여기에 적습니다. 없으면 ① 단계가 400 으로 끝납니다."},
    ],
}
_REC = ("확장자를 **허용 목록** 으로 가리고(서버에서, 이름이 아니라 내용도 함께), 올라간 파일의 이름은 서버가 새로 "
        "지어 붙이며(사용자가 준 이름을 경로로 쓰지 않는다), 저장 위치는 웹에서 실행되지 않는 디렉터리로 두고 "
        "그 경로에서 스크립트 실행을 끕니다. 이름의 `..`·역슬래시·널바이트는 받기 전에 거릅니다.")

STAGE = {"screen": "① 받는 구간", "basic": "② 기본", "deep": "③ 심화", "bypass": "④ 우회"}
MARK = "ttalkkak-upload-check"
# 받아 주면 서버에서 돌 수 있는 확장자 — 새싹에듀는 Tomcat 이라 .jsp 가 가장 위험하다
RUNNABLE = [(".jsp", "application/octet-stream"), (".jspx", "application/octet-stream"),
            (".php", "application/octet-stream"), (".html", "text/html")]
# 이름에 경로를 섞는 모양. 리터럴 역슬래시는 노션의 '과제 업로드 경로 조작' 건과 같은 모양이다
PATHS = ["../{m}.jsp", "..\\{m}.jsp", "....//{m}.jsp", "/etc/{m}.jsp", "..%2f{m}.jsp"]
# 검증이 있을 때 지나가 보는 모양
TRICKS = [("{m}.jsp.txt", "text/plain", "겹친 확장자"), ("{m}.JsP", "application/octet-stream", "대소문자 섞기"),
          ("{m}.jsp%00.txt", "text/plain", "널바이트"), ("{m}.jsp;.txt", "text/plain", "세미콜론"),
          # 이름은 .jsp 그대로 두고 Content-Type 만 그림으로 속인다. 이름 대신 Content-Type 으로만
          # 가리는 서버가 지나간다. 이름까지 .txt 로 바꾸면 ① 과 같은 요청이 되어 아무것도 못 가린다
          ("{m}.jsp", "image/png", "Content-Type 만 그림으로")]
OK = range(200, 300)


def _extra(text: str):
    out = []
    for line in (text or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip():
                out.append((k.strip(), v.strip()))
    return out


def multipart(field: str, filename: str, content_type: str, body: bytes, extra=()):
    """multipart/form-data 본문을 손으로 만든다 → (바이트, Content-Type).

    파일 이름에 `..` 나 역슬래시를 **그대로** 실어야 하는 점검이라 라이브러리를 쓰지 않는다 —
    대개의 라이브러리가 이름을 미리 깨끗하게 만들어 버려 점검이 성립하지 않는다.
    """
    sep = "----ttalkkak" + uuid.uuid4().hex[:12]
    parts = []
    for k, v in extra:
        parts.append(f'--{sep}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{sep}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                 f'Content-Type: {content_type}\r\n\r\n'.encode() + body + b"\r\n")
    parts.append(f"--{sep}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={sep}"


def real_url(url: str) -> str:
    """경로 틀의 `{변수}` 를 실제로 응답하는 번호로 채운다 — 못 찾으면 1.

    과제 제출 업로드(`/backend/lectures/{lid}/assignments/file`)처럼 업로드 자리는 대개 경로 틀로
    모인다. 틀 그대로 POST 하면 404 라 ① 에서 떨어진다. 번호 찾기는 probe.path_ids 가 한다
    (한 단계 위 목록을 읽어 진짜 번호를 거두고, 실행 안에서 한 번만 찾아 재사용한다).
    """
    if "{" not in url:
        return url
    for name, got in probe.path_ids(url).items():
        url = url.replace("{" + name + "}", got or "1")
    return re.sub(r"\{[^}/]+\}", "1", url)


def run(target, points, params):
    field = (params.get("field") or "file").strip()
    extra = _extra(params.get("extra"))
    out = []
    for p in points:
        lines, verdict, keep, title = [], "safe", None, ""
        mark = MARK + "-" + uuid.uuid4().hex[:6]
        content = f"{mark}\n점검용 파일입니다. 지워도 됩니다.\n".encode()
        url = real_url(p.url)

        def note(stage, text):
            lines.append(f"{STAGE[stage]} {text}")

        if url != p.url:
            note("screen", f"경로 틀을 실제 번호로 채움: {p.url} → {url}")

        def send(filename, ctype):
            body, head = multipart(field, filename, ctype, content, extra)
            return core.fetch(url, method="POST", raw_body=body, content_type=head)

        def send_without_file():
            """파일 칸만 빼고 같은 요청을 보낸다 — 응답이 같으면 파일을 보고 있지 않다는 뜻이다."""
            sep = "----ttalkkak" + uuid.uuid4().hex[:12]
            parts = [f'--{sep}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
                     for k, v in extra]
            parts.append(f"--{sep}--\r\n".encode())
            return core.fetch(url, method="POST", raw_body=b"".join(parts),
                              content_type=f"multipart/form-data; boundary={sep}")

        def gave_up(text, resp):
            """때려 보지 못하고 끝났다 — **안전이 아니라 '확인 못 함'** 이다."""
            note("screen", text)
            out.append(Check(point=p, verdict="unknown", evidence="\n".join(lines), response=resp,
                             recommendation=_REC))

        # ① 받는 구간 — 무해한 .txt
        r0 = send(f"{mark}.txt", "text/plain")
        note("screen", f"POST {url}  [{field}={mark}.txt] → {r0.status} · {len(r0.body)}B")
        if r0.status in (401, 403):
            gave_up(f"{r0.status} — 로그인이 필요한 자리다. 대상 탭의 **2. 인증** 에 테스트 계정 토큰을 "
                    "넣고 다시 돌리세요(토큰이 만료됐을 수도 있습니다)", r0)
            continue
        if r0.status not in OK:
            gave_up(f"무해한 .txt 도 {r0.status} — 업로드 자리가 아니거나 다른 칸이 더 필요합니다. "
                    f"칸 이름을 '{field}' 로 보냈습니다 — HAR 에서 본 multipart 의 파일 칸 이름과 "
                    "같이 보낼 값(lectureId 등)을 설정에 적고 다시 돌리세요", r0)
            continue
        # 2xx 라고 다 받는 자리는 아니다 — 받는 자리인지 두 가지로 가린다
        if "html" in r0.header("Content-Type").lower() or r0.body.lstrip()[:9].lower().startswith("<!doctype"):
            gave_up("올렸는데 **화면(HTML)** 이 돌아옴 — 업로드를 처리한 자리가 아니다. "
                    "앱이 POST 에도 그 주소의 화면을 그려 주는 것뿐이다", r0)
            continue
        bare = send_without_file()
        note("screen", f"파일 칸을 빼고 같은 요청: → {bare.status} · {len(bare.body)}B")
        if bare.status == r0.status and bare.body == r0.body:
            gave_up(f"파일을 보내나 안 보내나 **같은 응답** — 이 주소는 '{field}' 칸을 보고 있지 않다. "
                    "칸 이름이 맞는지 보세요", r0)
            continue
        keep = r0
        # ② 기본 — 그냥 돌 수 있는 확장자
        for ext, ctype in RUNNABLE:
            r = send(f"{mark}{ext}", ctype)
            note("basic", f"{ext}: → {r.status} · {len(r.body)}B")
            if r.status in OK:
                note("basic", f"{ext} 를 그대로 받아 줌 — 확장자 검증이 없다")
                verdict, keep, title = "vuln", r, "업로드 확장자 검증 없음"   # 어떤 확장자인지는 근거에
                break
        # ③ 심화 — 이름에 경로 섞기
        if verdict == "safe":
            for shape in PATHS:
                name = shape.format(m=mark)
                r = send(name, "application/octet-stream")
                note("deep", f"이름에 경로({name}): → {r.status} · {len(r.body)}B")
                if r.status in OK:
                    note("deep", "경로를 섞은 이름을 받아 줌 — 올릴 자리를 고를 수 있다(쉘 파일을 실행되는 경로에 둘 수 있음)")
                    verdict, keep, title = "vuln", r, "업로드 이름의 경로 조작 통과"
                    break
        # ④ 우회 — 검증이 있을 때 지나가 보기
        if verdict == "safe":
            for shape, ctype, kind in TRICKS:
                name = shape.format(m=mark)
                r = send(name, ctype)
                note("bypass", f"{kind}({name}): → {r.status} · {len(r.body)}B")
                if r.status in OK:
                    note("bypass", f"{kind} 로 검증을 지나감 — 저장된 이름을 확인하세요")
                    verdict, keep, title = "potential", r, "업로드 검증 우회(저장 이름 확인 필요)"
                    break
        if verdict == "safe":
            note("bypass", ".txt 만 받고 돌 수 있는 확장자·경로 섞은 이름·우회 모양은 모두 막힘")
        else:
            note("bypass", f"남은 파일을 지우세요 — 표식 {mark} 로 찾습니다")
        out.append(Check(point=p, verdict=verdict, evidence="\n".join(lines), response=keep, title=title,
                         severity="critical" if verdict == "vuln" else "medium", recommendation=_REC))
    return out
