"""연습용 대상 — 대시보드 모듈을 실서버 대신 시험할 때 쓴다. python demo_target.py → http://127.0.0.1:5051

일부러 입력값을 그대로 돌려주는 곳이 있다. 127.0.0.1 에서만 열고, 데이터는 저장하지 않는다.
| 경로              | 하는 일                        | 반사 확인 판정 |
| /search?q=        | 본문에 그대로                  | 취약          |
| /profile?name=    | input value 속성에 그대로       | 취약          |
| /news?q=          | HTML 인코딩해서               | 잠재          |
| /api/items?keyword= | JSON 으로                    | 잠재          |
| /about?ref=       | 돌려주지 않음                  | 안전          |
| POST /guestbook   | 받은 글을 그대로(저장 안 함)     | 취약          |
"""
import json

from flask import Flask, Response, request
from markupsafe import escape

app = Flask(__name__)

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
"""


@app.get("/")
def home():
    return HOME


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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5051, debug=False)
