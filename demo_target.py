"""연습용 대상 — 대시보드 모듈을 실서버 대신 시험할 때 쓴다. python demo_target.py → http://127.0.0.1:5051

일부러 입력값을 그대로 돌려주는 곳이 있다. 127.0.0.1 에서만 열고, 데이터는 저장하지 않는다.
| 경로              | 하는 일                        | 반사 확인 판정 |
| /search?q=        | 본문에 그대로                  | 취약          |
| /profile?name=    | input value 속성에 그대로       | 취약          |
| /news?q=          | HTML 인코딩해서               | 잠재          |
| /api/items?keyword= | JSON 으로                    | 잠재          |
| /about?ref=       | 돌려주지 않음                  | 안전          |
| POST /guestbook   | 받은 글을 그대로(저장 안 함)     | 취약          |
| /admin, /config.json | 링크 없음 — 사전으로만 찾힘 | —            |
| POST /backend/login | 토큰 발급(계정은 아래 ACCOUNTS) | —          |
| /backend/me       | 토큰이 맞는지 확인             | —            |

인증이 필요한 모듈을 여기서 먼저 돌려 볼 수 있게 로그인을 뒀다. 계정은 이 파일에
그대로 적어 두고 첫 화면에도 띄운다 — 다 가짜고, 안 보이면 기능을 돌려 볼 수가 없다.
"""
import base64
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from urllib.parse import unquote

from flask import Flask, Response, request
from markupsafe import escape

app = Flask(__name__)

# ── 연습용 계정 ───────────────────────────────────────────────
# 전부 가짜다. 이 서버는 127.0.0.1 에서만 열리고 아무것도 저장하지 않는다.
# 숨기지 않는 이유: 로그인 기능을 시험해 보려면 넣을 값이 보여야 한다.
ACCOUNTS = {
    "demo@sesacedu.test": {"pw": "demo1234", "role": "STUDENT", "auth": 1, "userId": 101},
    "teacher@sesacedu.test": {"pw": "teach1234", "role": "INSTRUCTOR", "auth": 2, "userId": 104},
}


def _b64(blob) -> str:
    return base64.urlsafe_b64encode(json.dumps(blob, separators=(",", ":")).encode()).decode().rstrip("=")


def _fake_jwt(email: str, who: dict) -> str:
    """JWT 모양만 흉내 낸 글자열. 서명이 없어 진짜 서버에서는 안 통한다."""
    return "%s.%s.demo-signature-not-real" % (
        _b64({"alg": "HS256", "typ": "JWT"}),
        _b64({"sub": email, "role": who["role"], "auth": who["auth"], "userId": who["userId"]}),
    )


def _envelope(code, message, result, status=200):
    """실서버와 같은 봉투 {code, message, result} — 대시보드가 토큰을 찾는 자리를 맞춰 둔다."""
    return Response(json.dumps({"code": code, "message": message, "result": result},
                               ensure_ascii=False),
                    status=status, mimetype="application/json")

# ── 연습용 모래상자 ───────────────────────────────────────────
# 경로 조작·SQL 주입을 실제로 시험할 수 있게, 진짜처럼 동작하되
# 이 폴더 밖으로는 절대 나가지 않는 가짜 서버 한 채를 임시 폴더에 만든다.
SANDBOX = Path(tempfile.gettempdir()) / "vcd-demo-root"
FILES = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndemo:x:1000:1000:demo:/home/demo:/bin/sh\n",
    "etc/nginx/sites-enabled/default": "server {\n  listen 80;\n  root /srv/demo;\n}\n",
    "srv/demo/material/강의자료.pdf": "(연습용 자료 파일)\n",
}


def _setup():
    for rel, body in FILES.items():
        path = SANDBOX / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    db = sqlite3.connect(SANDBOX / "demo.sqlite3")
    db.executescript("""
        DROP TABLE IF EXISTS members; DROP TABLE IF EXISTS lectures;
        CREATE TABLE members (id INTEGER, mail TEXT, uname TEXT);
        CREATE TABLE lectures (id INTEGER, title TEXT, is_open INTEGER);
        INSERT INTO members VALUES (1, 'demo@example.test', '연습계정'), (2, 'two@example.test', 'TWO');
    """)
    # 41개 중 35개만 공개 — 실제 서버와 같은 '참 41 / 거짓 35' 모양이 된다
    db.executemany("INSERT INTO lectures VALUES (?, ?, ?)",
                   [(i, f"강의 {i}", 1 if i <= 35 else 0) for i in range(1, 42)])
    db.commit()
    db.close()


_setup()

HOME = """<!doctype html><meta charset="utf-8"><title>연습용 대상</title>
<h1>연습용 대상</h1>
<ul>
  <li><a href="/search?q=hello">검색</a></li>
  <li><a href="/profile?name=guest">프로필</a></li>
  <li><a href="/news?q=today">뉴스</a></li>
  <li><a href="/about?ref=home">소개</a></li>
</ul>
<form action="/search" method="get"><input name="q" value="sql"><button>찾기</button></form>
<form action="/guestbook" method="post"><input name="name"><textarea name="message"></textarea><button>남기기</button></form>
<script>fetch('/api/items?keyword=a')</script>
<h2>연습용 계정</h2>
<p>전부 가짜입니다. <code>POST /backend/login</code> 에
<code>{"email": ..., "pw": ...}</code> 로 보내면 <code>result.token</code> 에 토큰이 옵니다.</p>
<table border="1" cellpadding="4">
<tr><th>이메일</th><th>비밀번호</th><th>권한</th></tr>
__ACCOUNT_ROWS__
</table>
<p>받은 토큰은 <code>GET /backend/me</code> 에 <code>Authorization: Bearer ...</code> 로 넣어 확인합니다.</p>
"""


@app.get("/")
def home():
    rows = "\n".join(
        "<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>"
        % (email, who["pw"], who["role"]) for email, who in ACCOUNTS.items())
    return HOME.replace("__ACCOUNT_ROWS__", rows)


@app.get("/search")
def search():
    return f"<p>검색어: {request.args.get('q', '')}</p>"  # 일부러 인코딩 안 함


@app.get("/profile")
def profile():
    return f'<input name="name" value="{request.args.get("name", "")}">'  # 일부러 인코딩 안 함


@app.get("/news")
def news():
    return f"<p>뉴스 검색: {escape(request.args.get('q', ''))}</p>"


@app.get("/api/items")
def items():
    return Response(json.dumps({"keyword": request.args.get("keyword", ""), "items": []}), mimetype="application/json")


@app.get("/about")
def about():
    return "<p>연습용 대상입니다.</p>"


@app.post("/guestbook")
def guestbook():
    return f"<p>{request.form.get('name', '')}: {request.form.get('message', '')}</p>"  # 저장하지 않고 돌려주기만


# ── 링크로는 어디서도 가리키지 않는 경로 ────────────
# 페이지를 따라가는 수집으로는 찾지 못하고, 사전으로 이름을 찍어야 나온다.

@app.get("/admin")
def admin():
    return "<h1>관리 화면(연습용)</h1><p>아무 데서도 여기로 링크하지 않는다.</p>"


@app.get("/config.json")
def config_json():
    return Response(json.dumps({"app": "demo", "debug": True}), mimetype="application/json")


# ── 새싹에듀와 같은 모양의 허점 두 개 ─────────────────────────
# 도구 모듈을 실서버 대신 여기서 시험하려고 똑같은 모양으로 만들어 뒀다.

@app.get("/backend/lectures/<int:lid>/material/download")
def material_download(lid):
    """자료 다운로드 — '../ 제거'를 디코딩보다 먼저 해서 이중 인코딩에 뚫린다.

    읽는 범위는 임시 폴더 안의 가짜 서버(SANDBOX)로 못 박아 둔다.
    """
    if not request.headers.get("Authorization", "").startswith("Bearer "):
        return Response('{"error":"unauthorized"}', status=401, mimetype="application/json")

    name = request.args.get("file", "")        # 들어올 때 이미 한 번 디코딩된 상태
    cleaned = name.replace("../", "")          # ① ../ 를 먼저 지우고
    decoded = unquote(cleaned)                 # ② 그다음 디코딩한다 ← 여기서 되살아난다

    if "../" in decoded:                       # 올라가기가 통한 경우
        path = SANDBOX / decoded.replace("../", "")
    else:
        path = SANDBOX / "srv/demo/material" / decoded

    real = os.path.realpath(path)
    if not real.startswith(str(SANDBOX.resolve())) or not os.path.isfile(real):
        return Response("not found", status=404)
    return Response(Path(real).read_text(encoding="utf-8", errors="replace"), mimetype="text/plain")


@app.get("/backend/lectures")
def lectures():
    """강의 목록 — 검색어를 SQL 에 그대로 이어 붙인다. 건수 차이로 참·거짓이 드러난다."""
    keyword = request.args.get("keyword", "")
    sql = f"SELECT COUNT(*) FROM lectures WHERE is_open = 1 AND title LIKE '%{keyword}%'"
    db = sqlite3.connect(f"file:{SANDBOX / 'demo.sqlite3'}?mode=ro", uri=True)  # 읽기 전용으로 연다
    try:
        total = db.execute(sql).fetchone()[0]
    except sqlite3.Error as e:
        return Response(json.dumps({"error": str(e)}), status=500, mimetype="application/json")
    finally:
        db.close()
    return Response(json.dumps({"page": {"total": total}}), mimetype="application/json")


# ── 로그인 ────────────────────────────────────────────────────
# 주소·보내는 모양·응답 봉투를 실서버와 똑같이 맞췄다. 여기서 되면 거기서도 된다.

@app.post("/backend/login")
def login():
    body = request.get_json(silent=True) or {}
    email, pw = str(body.get("email", "")), str(body.get("pw", ""))
    missing = [{"field": f, "message": "필수입니다."} for f, v in (("email", email), ("pw", pw)) if not v]
    if missing:
        return _envelope("INVALID_INPUT", "입력값을 확인해주세요.", {"errors": missing}, status=400)
    who = ACCOUNTS.get(email)
    if not who or who["pw"] != pw:
        # 어느 쪽이 틀렸는지 알려 주지 않는다 — 실서버도 그렇다.
        return _envelope("LOGIN_FAILED", "이메일 또는 비밀번호가 올바르지 않습니다.", None, status=400)
    token = _fake_jwt(email, who)
    return _envelope("SUCCESS", "로그인 성공", {
        "token": token,
        "authorizationHeader": "Bearer " + token,
        "role": who["role"], "auth": who["auth"], "userId": who["userId"],
    })


@app.get("/backend/me")
def me():
    """토큰이 제대로 붙었는지 보는 자리. 서명은 확인하지 않는다 — 연습용이다."""
    raw = request.headers.get("Authorization", "")
    if not raw.startswith("Bearer "):
        return _envelope("UNAUTHORIZED", "인증 헤더가 없습니다.", None, status=401)
    body = raw[7:].split(".")
    if len(body) != 3:
        return _envelope("UNAUTHORIZED", "토큰 모양이 아닙니다.", None, status=401)
    try:
        claims = json.loads(base64.urlsafe_b64decode(body[1] + "=" * (-len(body[1]) % 4)))
    except Exception:
        return _envelope("UNAUTHORIZED", "토큰을 읽을 수 없습니다.", None, status=401)
    return _envelope("SUCCESS", "확인됨", claims)


if __name__ == "__main__":
    # 5051 이 이미 쓰이고 있으면 DEMO_PORT 로 옮긴다 (대상 등록 주소도 같이 바꿔야 한다)
    app.run(host="127.0.0.1", port=int(os.environ.get("DEMO_PORT", "5051")), debug=False)
