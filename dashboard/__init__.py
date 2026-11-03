import os
from pathlib import Path

from flask import Flask

from . import db
from .core import SEVERITY_LABEL, fmt_kst
from .registry import load_catalog

# 범용 대상의 허용 범위. 프로젝트 대상은 projects/<id>/__init__.py 의 scope 를 쓴다.
DEFAULT_SCOPE = "localhost,127.0.0.1"


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("DASH_SECRET", os.urandom(16).hex()),
        DATABASE=os.path.join(app.instance_path, "dashboard.sqlite3"),
        SCOPE_HOSTS=[h.strip().lower() for h in os.environ.get("DASH_SCOPE", DEFAULT_SCOPE).split(",") if h.strip()],
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
    app.jinja_env.filters["kst"] = fmt_kst
    app.jinja_env.globals["SEVERITY_LABEL"] = SEVERITY_LABEL
    app.jinja_env.globals["STATUSES"] = db.STATUSES
    app.jinja_env.globals["PROJECTS"] = app.config["PROJECTS"]

    from .routes import bp
    app.register_blueprint(bp)
    return app
