import os
import re
import secrets
from pathlib import Path

from flask import Flask, abort, request, session
from markupsafe import Markup, escape

from . import db, wordlists
from .core import SEVERITY_LABEL, fmt_kst
from .registry import group_targets, load_catalog

__version__ = "0.2.0"

# 범용 대상의 허용 범위. 프로젝트 대상은 projects/<id>/__init__.py 의 scope 를 쓴다.
DEFAULT_SCOPE = "localhost,127.0.0.1"
# 내 PC 에서 띄웠을 때 들어오는 이름. 이것 말고는 DASH_ALLOWED_HOSTS 에 적어야 들어온다.
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
TOKEN = re.compile(r"(vcd[0-9a-f]{8})")


def _secret_key(instance: Path) -> str:
    """재시작해도 세션(CSRF 토큰)이 유지되도록 instance/ 에 키를 둔다."""
    path = instance / "secret.key"
    if not path.exists():
        path.write_text(secrets.token_hex(32), encoding="ascii")
    return path.read_text(encoding="ascii").strip()


def mark_tokens(text) -> Markup:
    """요청 기록에서 점검 표식(vcd + 8자)을 눈에 띄게. 먼저 이스케이프하고 표식만 감싼다."""
    return Markup(TOKEN.sub(r"<mark>\1</mark>", str(escape(text or ""))))


STRONG = re.compile(r"\*\*(.+?)\*\*", re.S)


def strong(text) -> Markup:
    """글 속의 **강조** 를 굵게. 모듈이 설명에 쓰는 표시인데 그동안 별 두 개가 그대로 보였다.

    먼저 이스케이프하고 나서 표시만 감싼다 — 모듈 글에 든 꺾쇠가 태그가 되지 않게.
    """
    return Markup(STRONG.sub(r"<b>\g<1></b>", str(escape(text or ""))))


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    instance = Path(app.instance_path)
    instance.mkdir(parents=True, exist_ok=True)
    env = os.environ.get
    app.config.from_mapping(
        SECRET_KEY=env("DASH_SECRET") or _secret_key(instance),
        DATABASE=str(instance / "dashboard.sqlite3"),
        SCOPE_HOSTS=[h.strip().lower() for h in env("DASH_SCOPE", DEFAULT_SCOPE).split(",") if h.strip()],
        SELF_PORT=int(env("DASH_PORT", "5050")),           # 이 주소는 점검 대상에서 뺀다
        # 들어와도 되는 Host 이름. 기본은 내 PC 뿐이고, 서버에 올려 밖에서 열 때만 적는다.
        # `*` 는 아무 이름이나 받는다 — 공인 IP 가 중지·시작마다 바뀌는 자리용.
        ALLOWED_HOSTS=[h.strip().lower() for h in env("DASH_ALLOWED_HOSTS", "").split(",") if h.strip()],
        DELAY_MS=int(env("DASH_DELAY_MS", "100")),         # 요청 사이 간격
        # 실행 하나당 요청 수 한도. 경로 조작 퍼징이 서버 구조 전체를 한 번에 그리는 데
        # 3,000 쯤 쓴다(11-04 실측 1,342 + JSP 앱 안쪽). 그보다 작으면 트리가 반쪽이 된다.
        MAX_REQUESTS=int(env("DASH_MAX_REQUESTS", "6000")),
        CSRF=True,
        MODULES_PKG="modules",
        PROJECTS_PKG="projects",
    )
    if test_config:
        app.config.update(test_config)

    app.teardown_appcontext(db.close_db)
    with app.app_context():
        db.init_db()

    app.config["PROJECTS"], app.config["MODULES"], app.config["MODULE_ERRORS"] = load_catalog(
        app.config["SCOPE_HOSTS"], app.config["MODULES_PKG"], app.config["PROJECTS_PKG"])

    @app.before_request
    def _protect():
        # 다른 이름으로 들어온 요청(DNS 리바인딩)과 다른 사이트가 몰래 보낸 POST(CSRF)를 막는다
        host = (request.host or "").rsplit(":", 1)[0].strip("[]").lower()
        allowed = app.config["ALLOWED_HOSTS"]
        if host not in LOCAL_HOSTS and "*" not in allowed and host not in allowed:
            abort(400, "허용되지 않은 Host")
        if request.method == "POST" and app.config["CSRF"]:
            sent = request.form.get("_csrf", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "CSRF 토큰이 맞지 않습니다. 페이지를 새로 고친 뒤 다시 하세요")

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.filters["kst"] = fmt_kst
    app.jinja_env.filters["mark_tokens"] = mark_tokens
    app.jinja_env.filters["strong"] = strong
    # 대상 목록을 화면 묶음으로 — 연습용은 따로 뒤에 (registry.group_targets 가 규칙)
    app.jinja_env.filters["grouped"] = lambda ts: group_targets(ts, app.config["PROJECTS"])
    def csrf_field():
        return Markup('<input type="hidden" name="_csrf" value="%s">' % escape(csrf_token()))

    app.jinja_env.globals.update(SEVERITY_LABEL=SEVERITY_LABEL, STATUSES=db.STATUSES, PROJECTS=app.config["PROJECTS"],
                                 csrf_token=csrf_token, csrf_field=csrf_field, VERSION=__version__,
                                 wordlist_options=wordlists.available)

    from .routes import bp, module_needs
    app.jinja_env.globals["module_needs"] = module_needs
    app.register_blueprint(bp)
    return app
