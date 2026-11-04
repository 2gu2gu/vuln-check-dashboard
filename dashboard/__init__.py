import os
import re
import secrets
from pathlib import Path

from flask import Flask, abort, request, session
from markupsafe import Markup, escape

from . import db, wordlists
from .core import SEVERITY_LABEL, fmt_kst
from .registry import load_catalog

__version__ = "0.2.0"

# 범용 대상의 허용 범위. 프로젝트 대상은 projects/<id>/__init__.py 의 scope 를 쓴다.
DEFAULT_SCOPE = "localhost,127.0.0.1"
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
        DELAY_MS=int(env("DASH_DELAY_MS", "100")),         # 요청 사이 간격
        MAX_REQUESTS=int(env("DASH_MAX_REQUESTS", "2000")),  # 실행 하나당 요청 수 한도
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
        if (request.host or "").rsplit(":", 1)[0].strip("[]") not in ("127.0.0.1", "localhost", "::1"):
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
    def csrf_field():
        return Markup('<input type="hidden" name="_csrf" value="%s">' % escape(csrf_token()))

    app.jinja_env.globals.update(SEVERITY_LABEL=SEVERITY_LABEL, STATUSES=db.STATUSES, PROJECTS=app.config["PROJECTS"],
                                 csrf_token=csrf_token, csrf_field=csrf_field, VERSION=__version__,
                                 wordlist_options=wordlists.available)

    from .routes import bp, module_needs
    app.jinja_env.globals["module_needs"] = module_needs
    app.register_blueprint(bp)
    return app
