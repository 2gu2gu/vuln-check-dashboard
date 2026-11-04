import json
import re
import sqlite3
from urllib.parse import urlsplit

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, url_for)

from . import needs, scope, wordlists
from .attack import TACTIC_NAME, TACTIC_ORDER, TACTICS, technique_url
from .core import (SEVERITIES, SEVERITY_LABEL, VERDICTS, Check, Finding, Point, RunContext, Target,
                   ToolResult, fmt_kst, now_iso)
from .db import STATUSES, get_db
from .registry import GENERAL, modules_for

SECRET_NAME = re.compile(r"pass|secret|token|csrf|session|key", re.I)

bp = Blueprint("dash", __name__)

SEVERITY_ORDER_SQL = "CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " END"


def _modules():
    return current_app.config["MODULES"]


def _projects():
    return current_app.config["PROJECTS"]


def _project_of(target):
    return _projects().get(target["project"]) or _projects()[GENERAL]


def _modules_for(target):
    """대상이 있으면 범용 + 그 프로젝트 전용 중 역할이 맞는 것, 없으면 전부."""
    return modules_for(_modules(), target["project"], target["role"]) if target else _modules()


def _role_label(t):
    """대상의 역할을 사람이 읽는 이름으로. 터널로 열어 둔 경우 주소만 보고는 어디인지 모른다."""
    if not t or not t["role"]:
        return ""
    return _project_of(t).role_name(t["role"])


def _targets():
    return get_db().execute("SELECT * FROM targets ORDER BY project, id").fetchall()


def _current_target():
    """?target= 로 고른 대상. 없으면 첫 대상."""
    targets = _targets()
    tid = request.args.get("target", type=int)
    for t in targets:
        if tid is None or t["id"] == tid:
            return t, targets
    return (targets[0] if targets else None), targets


def _technique_tactic():
    """기법 ID → 그 기법을 쓰는 모듈의 전술 ID."""
    m = {}
    for mod in _modules().values():
        for a in mod.attack:
            m.setdefault(a["technique"], a["tactic"])
    return m


# ── 결과(메인) ────────────────────────────────────────────────

@bp.get("/")
def results():
    target, targets = _current_target()
    rows, counts = [], {s: 0 for s in SEVERITIES}
    if target:
        sql = "SELECT * FROM findings WHERE target_id = ?"
        args = [target["id"]]
        for key in ("severity", "module_id", "status"):
            val = request.args.get(key)
            if val:
                sql += f" AND {key} = ?"
                args.append(val)
        rows = get_db().execute(sql + f" ORDER BY {SEVERITY_ORDER_SQL}, id DESC", args).fetchall()
        for r in get_db().execute(
                "SELECT severity, COUNT(*) c FROM findings WHERE target_id = ? AND status != 'fixed' "
                "AND status != 'false_positive' GROUP BY severity", [target["id"]]):
            counts[r["severity"]] = r["c"]
    mods = _modules()
    data = [{
        **dict(r),
        "module_name": mods[r["module_id"]].name if r["module_id"] in mods else r["module_id"],
        "path": (r["location"].removeprefix(target["url"]) or "/") if r["location"] else "",
        "severity_label": SEVERITY_LABEL[r["severity"]],
        "status_label": STATUSES.get(r["status"], r["status"]),
        "technique_url": technique_url(r["technique"]) if r["technique"] else "",
        "created": fmt_kst(r["created_at"]),
    } for r in rows]
    return render_template("results.html", target=target, targets=targets, findings=data,
                           counts=counts, modules=_modules_for(target), severities=SEVERITIES, args=request.args)


@bp.post("/findings/<int:fid>/status")
def finding_status(fid):
    status = request.form.get("status")
    if status not in STATUSES:
        abort(400)
    db = get_db()
    row = db.execute("SELECT target_id FROM findings WHERE id = ?", [fid]).fetchone()
    if not row:
        abort(404)
    db.execute("UPDATE findings SET status = ? WHERE id = ?", [status, fid])
    db.commit()
    return redirect(url_for("dash.results", target=row["target_id"]))


# ── 대상 ──────────────────────────────────────────────────────

@bp.route("/targets", methods=["GET", "POST"])
def targets():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        url = request.form.get("url", "").strip().rstrip("/")
        pid = request.form.get("project", GENERAL)
        try:
            if pid not in _projects():
                raise ValueError(f"없는 프로젝트입니다: {pid}")
            if not name:
                raise ValueError("이름을 넣어 주세요")
            role = request.form.get("role", "").strip()
            project = _projects()[pid]
            if project.roles and role not in project.roles:
                raise ValueError(f"역할을 골라 주세요 ({', '.join(project.roles)})")
            # 역할을 고르면 그 서버의 범위(포트까지)로 검사한다
            scope.ensure_in_scope(url, project.role_scope(role))
            db.execute("INSERT INTO targets (project, role, name, url, note, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                       [pid, role, name, url, request.form.get("note", "").strip(), now_iso()])
            db.commit()
            flash(f"대상을 등록했습니다: {name}", "ok")
        except sqlite3.IntegrityError:
            flash(f"이미 등록된 주소입니다: {url}", "error")
        except Exception as e:  # noqa: BLE001
            flash(str(e), "error")
        return redirect(url_for("dash.targets"))
    target, targets = _current_target()
    names = {t["id"]: list(_parse_headers(t["headers"])) for t in targets}
    return render_template("targets.html", target=target, targets=targets, header_names=names)


@bp.post("/targets/<int:tid>/delete")
def target_delete(tid):
    db = get_db()
    db.execute("DELETE FROM targets WHERE id = ?", [tid])
    db.commit()
    flash("대상을 지웠습니다(결과 포함)", "ok")
    return redirect(url_for("dash.targets"))


def _parse_headers(text):
    """'이름: 값' 한 줄에 하나 → dict. 형식이 틀린 줄은 ValueError."""
    out = {}
    for n, line in enumerate((text or "").splitlines(), 1):
        if not line.strip():
            continue
        name, sep, value = line.partition(":")
        if not sep or not re.fullmatch(r"[A-Za-z0-9-]+", name.strip()):
            raise ValueError(f"{n}번째 줄 형식이 틀렸습니다 — '이름: 값'")
        out[name.strip()] = value.strip()
    return out


@bp.post("/targets/<int:tid>/headers")
def target_headers(tid):
    text = "" if request.form.get("clear") == "yes" else request.form.get("headers", "")
    if not text.strip() and request.form.get("clear") != "yes":
        flash("바꿀 내용이 없습니다. 지우려면 '지우기'를 누르세요", "error")
        return redirect(url_for("dash.targets", target=tid))
    try:
        hdrs = _parse_headers(text)
        db = get_db()
        db.execute("UPDATE targets SET headers = ? WHERE id = ?", [text.strip(), tid])
        db.commit()
        flash(f"인증 헤더 {len(hdrs)}개를 저장했습니다" if hdrs else "인증 헤더를 지웠습니다", "ok")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("dash.targets", target=tid))


# ── 모듈 ──────────────────────────────────────────────────────

@bp.get("/modules")
def modules():
    target, targets = _current_target()
    available = _modules_for(target)
    project = _project_of(target) if target else None
    groups = [("범용 모듈", "모든 대상에 쓰는 고정 모듈 · modules/", [m for m in available.values() if not m.project])]
    if target:
        if project.id != GENERAL:
            groups.append((f"{project.name} 전용", f"이 프로젝트 대상에만 보임 · {project.source}modules/",
                           [m for m in available.values() if m.project == project.id]))
    else:
        for p in _projects().values():
            if p.id != GENERAL:
                groups.append((f"{p.name} 전용", f"{p.source}modules/", [m for m in available.values() if m.project == p.id]))
    runs = get_db().execute(
        "SELECT runs.*, targets.name AS target_name, "
        "(SELECT COUNT(*) FROM findings f WHERE f.run_id = runs.id) AS n, "
        "(SELECT COUNT(*) FROM exchanges x WHERE x.run_id = runs.id) AS reqs "
        "FROM runs JOIN targets ON targets.id = runs.target_id ORDER BY runs.id DESC LIMIT 15").fetchall()
    return render_template("modules.html", groups=groups, all_modules=_modules(), project=project,
                           hidden=len(_modules()) - len(available), errors=current_app.config["MODULE_ERRORS"],
                           target=target, targets=targets, runs=runs, tactic_name=TACTIC_NAME)


def module_needs(mod, t=None):
    """이 모듈이 미리 준비해야 하는 것 + 지금 준비됐는지. 화면에서도 쓴다."""
    header_names = list(_parse_headers(t["headers"])) if t and t["headers"] else []
    return needs.check(mod, header_names)


def _guard(mod, t, back):
    """실행 전 확인. 문제가 있으면 돌아갈 redirect, 없으면 None."""
    if mod.project not in ("", t["project"]):
        flash(f"{mod.name} 은 {_projects()[mod.project].name} 전용 모듈입니다", "error")
        return redirect(back)
    if mod.kind == "active" and request.form.get("confirm") != "yes":
        flash("능동 모듈은 '자체 환경 확인'에 체크해야 실행됩니다", "error")
        return redirect(back)
    missing = needs.blocking(mod, list(_parse_headers(t["headers"])) if t["headers"] else [])
    if missing:
        n = missing[0]
        flash(f"{mod.name} 은 {n['label']}{(' ' + n['name']) if n['name'] else ''} 가 있어야 돌아갑니다 — {n['how']}", "error")
        return redirect(back)
    return None


def _check_types(mod, values):
    """입력값이 칸 종류에 맞는지 본다. 숫자 칸은 숫자, 고르는 칸은 목록 안의 값."""
    for p in mod.params:
        val = str(values.get(p["name"], "")).strip()
        label = p.get("label") or p["name"]
        if p.get("type") == "int" and not val.isdigit():
            raise ValueError(f"'{label}' 에는 숫자를 넣어 주세요")
        if p.get("type") == "select" and val not in [o["value"] for o in p.get("options", [])]:
            raise ValueError(f"'{label}' 은 목록에 있는 값이어야 합니다")
        if p.get("type") == "wordlist" and val not in [o["value"] for o in wordlists.available()["items"]]:
            raise ValueError(f"'{label}' 에 고른 사전을 찾을 수 없습니다")
    return values


def _read_params(mod, prefix=""):
    """화면 입력값 → 모듈 params."""
    values = {p["name"]: request.form.get(prefix + p["name"], p.get("default", "")) for p in mod.params}
    return _check_types(mod, values)


def _recorder(tid, mid):
    """core.fetch 가 요청마다 부른다. 실행이 실패해도 기록은 남도록 바로 커밋한다."""
    def record(x):
        db = get_db()
        cur = db.execute(
            "INSERT INTO exchanges (run_id, target_id, module_id, method, url, req_headers, req_body, status, "
            "resp_headers, resp_body, size, ms, error, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [g.run_id, tid, mid, x["method"], x["url"], json.dumps(x["req_headers"], ensure_ascii=False),
             x.get("req_body", ""), x.get("status", 0), json.dumps(x.get("resp_headers", []), ensure_ascii=False),
             x.get("resp_body", ""), x.get("size", 0), x.get("ms", 0), x.get("error", ""), now_iso()])
        db.commit()
        return cur.lastrowid
    return record


def _load_cache(tid, mid):
    """모듈이 지난번에 읽어 둔 값. 블라인드 추출처럼 비싼 작업을 다시 하지 않게 한다."""
    return {r["key"]: r["value"] for r in get_db().execute(
        "SELECT key, value FROM tool_cache WHERE target_id = ? AND module_id = ?", [tid, mid])}


def _save_cache(tid, mid, cache):
    db, now = get_db(), now_iso()
    db.executemany("INSERT INTO tool_cache (target_id, module_id, key, value, created_at) VALUES (?,?,?,?,?) "
                   "ON CONFLICT (target_id, module_id, key) DO UPDATE SET value = excluded.value",
                   [(tid, mid, k, v, now) for k, v in cache.items()])
    db.commit()


def _execute(mod, t, params, call):
    """실행 기록·범위·요청 설정·오류 처리를 한곳에서. call(target) 이 저장까지 하고 알림 문구를 돌려준다."""
    db, cfg = get_db(), current_app.config
    cur = db.execute("INSERT INTO runs (target_id, module_id, params, status, started_at) VALUES (?, ?, ?, 'running', ?)",
                     [t["id"], mod.id, json.dumps(params, ensure_ascii=False), now_iso()])
    g.run_id = cur.lastrowid
    db.commit()
    # 실행 중 core.fetch 는 이 범위로만 나간다 — 역할을 골랐으면 그 서버의 포트까지
    g.scope_hosts = _project_of(t).role_scope(t["role"])
    # 포트를 가리지 않는 일(포트 스캔)은 프로젝트 호스트 목록으로만 검사한다
    g.host_scope = _project_of(t).scope
    g.run_ctx = RunContext(t["url"], _parse_headers(t["headers"]), cfg["DELAY_MS"], cfg["MAX_REQUESTS"],
                           _recorder(t["id"], mod.id), cache=_load_cache(t["id"], mod.id))
    try:
        scope.ensure_in_scope(t["url"])
        msg = call(Target(t["id"], t["name"], t["url"]))
        db.execute("UPDATE runs SET status = 'done', finished_at = ? WHERE id = ?", [now_iso(), g.run_id])
        flash(f"{mod.name}: {msg} · 요청 {g.run_ctx.count}개", "ok")
    except Exception as e:  # noqa: BLE001 — 실패도 실행 기록에 남긴다
        db.rollback()
        db.execute("UPDATE runs SET status = 'error', error = ?, finished_at = ? WHERE id = ?",
                   [str(e), now_iso(), g.run_id])
        flash(f"{mod.name} 실패: {e}", "error")
    finally:
        # 중간에 멈춰도 그때까지 읽은 값은 남겨 둔다
        _save_cache(t["id"], mod.id, g.run_ctx.cache)
        g.pop("scope_hosts", None)
        g.pop("host_scope", None)
        g.pop("run_ctx", None)
    db.commit()


def _save_finding(mod, tid, f):
    """같은 대상·모듈·제목·위치면 새로 쌓지 않고 갱신한다. 조치됨이었는데 다시 나오면 미확인으로 되돌린다(재발)."""
    db, now = get_db(), now_iso()
    tech = f.technique or mod.attack[0]["technique"]
    xid = getattr(f.response, "exchange_id", 0) or None
    row = db.execute("SELECT id, status FROM findings WHERE target_id = ? AND module_id = ? AND title = ? AND location = ?",
                     [tid, mod.id, f.title, f.location]).fetchone()
    if row:
        status = "open" if row["status"] == "fixed" else row["status"]
        db.execute("UPDATE findings SET run_id = ?, severity = ?, evidence = ?, recommendation = ?, technique = ?, "
                   "status = ?, last_seen = ?, exchange_id = ? WHERE id = ?",
                   [g.run_id, f.severity, f.evidence, f.recommendation, tech, status, now, xid, row["id"]])
        return False
    db.execute("INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, "
               "recommendation, technique, created_at, last_seen, exchange_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               [g.run_id, tid, mod.id, f.title, f.severity, f.location, f.evidence, f.recommendation, tech, now, now, xid])
    return True


def _save_points(mod, tid, points):
    db, now = get_db(), now_iso()
    new = skipped = 0
    for p in points:
        if not isinstance(p, Point):
            raise TypeError("수집 모듈의 run() 은 Point 목록을 돌려줘야 합니다")
        if not scope.is_in_scope(p.url, g.scope_hosts):
            skipped += 1
            continue
        sample = "" if SECRET_NAME.search(p.param) else p.sample[:200]
        exists = db.execute("SELECT 1 FROM points WHERE target_id = ? AND method = ? AND url = ? AND param = ? AND place = ?",
                            [tid, p.method, p.url, p.param, p.place]).fetchone()
        db.execute(
            "INSERT INTO points (target_id, method, url, param, place, sample, source, module_id, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (target_id, method, url, param, place) DO UPDATE SET "
            "last_seen = excluded.last_seen, sample = CASE WHEN excluded.sample != '' THEN excluded.sample ELSE sample END",
            [tid, p.method, p.url, p.param, p.place, sample, p.source, mod.id, now, now])
        new += not exists
    return new, skipped


@bp.post("/modules/<mid>/run")
def module_run(mid):
    mod = _modules().get(mid) or abort(404)
    t = get_db().execute("SELECT * FROM targets WHERE id = ?", [request.form.get("target_id", type=int)]).fetchone()
    if not t:
        flash("대상을 먼저 고르세요", "error")
        return redirect(url_for("dash.modules"))
    if mod.stage == "probe":
        flash(f"{mod.name} 은 지점 점검 모듈입니다. 표면 탭에서 지점을 골라 실행하세요", "error")
        return redirect(url_for("dash.surface", target=t["id"]))
    if mod.stage == "tool":
        return redirect(url_for("dash.tools", target=t["id"], tool=mid))
    stop = _guard(mod, t, url_for("dash.modules", target=t["id"]))
    if stop:
        return stop
    try:
        params = _read_params(mod)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("dash.modules", target=t["id"]))

    if mod.stage == "collect":
        def call(target):
            points = mod.run(target, params) or []
            new, skipped = _save_points(mod, t["id"], points)
            return f"지점 {len(points) - skipped}개 수집(새로 {new})" + (f", 범위 밖 {skipped}개 제외" if skipped else "")
        _execute(mod, t, params, call)
        return redirect(url_for("dash.surface", target=t["id"]))

    def call(target):
        results = mod.run(target, params) or []
        for f in results:
            if not isinstance(f, Finding):
                raise TypeError("run() 은 Finding 목록을 돌려줘야 합니다")
        new = sum(_save_finding(mod, t["id"], f) for f in results)
        return f"{len(results)}건 발견(새로 {new})"
    _execute(mod, t, params, call)
    return redirect(url_for("dash.results", target=t["id"]))


# ── 표면(수집된 지점) ─────────────────────────────────────────

def _probe_modules(target):
    return {k: m for k, m in _modules_for(target).items() if m.stage == "probe"}


@bp.get("/surface")
def surface():
    target, targets = _current_target()
    groups, totals = [], {"endpoints": 0, "params": 0, **{v: 0 for v in VERDICTS}}
    if target:
        db = get_db()
        checks = {}
        for c in db.execute("SELECT pc.* FROM point_checks pc JOIN points p ON p.id = pc.point_id WHERE p.target_id = ?",
                            [target["id"]]):
            checks.setdefault(c["point_id"], []).append(c)
        by_url = {}
        for p in db.execute("SELECT * FROM points WHERE target_id = ? ORDER BY url, method, place, param", [target["id"]]):
            grp = by_url.setdefault(p["url"], {"url": p["url"], "path": urlsplit(p["url"]).path or "/",
                                               "methods": set(), "sources": set(), "params": []})
            grp["methods"].add(p["method"])
            grp["sources"].add(p["source"])
            if p["param"]:
                grp["params"].append({**dict(p), "checks": [
                    {"module": _modules()[c["module_id"]].name if c["module_id"] in _modules() else c["module_id"],
                     "verdict": c["verdict"], "evidence": c["evidence"], "exchange_id": c["exchange_id"]}
                    for c in checks.get(p["id"], [])]})
                totals["params"] += 1
                for c in checks.get(p["id"], []):
                    totals[c["verdict"]] += 1
        groups = list(by_url.values())
        totals["endpoints"] = len(groups)
    return render_template("surface.html", groups=groups, totals=totals, probes=_probe_modules(target),
                           collectors=[m for m in _modules_for(target).values() if m.stage == "collect"],
                           verdicts=VERDICTS, target=target, targets=targets)


@bp.post("/surface/probe")
def surface_probe():
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [request.form.get("target_id", type=int)]).fetchone() or abort(404)
    back = url_for("dash.surface", target=t["id"])
    mod = _probe_modules(t).get(request.form.get("module_id", "")) or abort(404)
    ids = request.form.getlist("point", type=int)
    if not ids:
        flash("점검할 지점을 고르세요", "error")
        return redirect(back)
    stop = _guard(mod, t, back)
    if stop:
        return stop
    try:
        params = _read_params(mod, f"{mod.id}__")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(back)

    marks = ",".join("?" * len(ids))
    rows = db.execute(f"SELECT * FROM points WHERE target_id = ? AND param != '' AND id IN ({marks})", [t["id"], *ids]).fetchall()
    points = []
    for r in rows:
        siblings = db.execute("SELECT param, sample FROM points WHERE target_id = ? AND url = ? AND method = ? AND place = ? "
                              "AND param != ''", [t["id"], r["url"], r["method"], r["place"]])
        points.append(Point(method=r["method"], url=r["url"], param=r["param"], place=r["place"], sample=r["sample"],
                            source=r["source"], id=r["id"], fields={s["param"]: s["sample"] for s in siblings}))

    def call(target):
        checks = mod.run(target, points, params) or []
        counts = {v: 0 for v in VERDICTS}
        for c in checks:
            if not isinstance(c, Check):
                raise TypeError("지점 점검 모듈의 run() 은 Check 목록을 돌려줘야 합니다")
            counts[c.verdict] += 1
            xid = getattr(c.response, "exchange_id", 0) or None
            db.execute("INSERT INTO point_checks (point_id, module_id, verdict, evidence, checked_at, exchange_id) "
                       "VALUES (?,?,?,?,?,?) ON CONFLICT (point_id, module_id) DO UPDATE SET verdict = excluded.verdict, "
                       "evidence = excluded.evidence, checked_at = excluded.checked_at, exchange_id = excluded.exchange_id",
                       [c.point.id, mod.id, c.verdict, c.evidence, now_iso(), xid])
            if c.verdict == "vuln":
                p = c.point
                _save_finding(mod, t["id"], Finding(
                    title=c.title or mod.name, severity=c.severity or mod.severity, evidence=c.evidence,
                    location=f"{p.url} ({p.place}: {p.param})", recommendation=c.recommendation, response=c.response))
        skipped = len(points) - len(checks)
        return (f"지점 {len(checks)}개 — " + " · ".join(f"{VERDICTS[v]} {n}" for v, n in counts.items())
                + (f", 건너뜀 {skipped}" if skipped else ""))
    _execute(mod, t, {**params, "points": len(points)}, call)
    return redirect(back)


@bp.post("/surface/clear")
def surface_clear():
    tid = request.form.get("target_id", type=int)
    db = get_db()
    db.execute("DELETE FROM points WHERE target_id = ?", [tid])
    db.commit()
    flash("수집된 지점을 비웠습니다(결과 탭의 결과는 남음)", "ok")
    return redirect(url_for("dash.surface", target=tid))


# ── 도구(값을 넣고 바로 결과를 보는 모듈) ────────────────────

def _tool_modules(target):
    return {k: m for k, m in _modules_for(target).items() if m.stage == "tool"}


def _tool_page(target, targets, mod, values, result=None):
    tools = _tool_modules(target)
    return render_template("tools.html", tools=tools, mod=mod, values=values, result=result,
                           target=target, targets=targets)


@bp.get("/tools")
def tools():
    target, targets = _current_target()
    tools_ = _tool_modules(target)
    mod = tools_.get(request.args.get("tool") or "") or (next(iter(tools_.values())) if tools_ else None)
    values = {p["name"]: p.get("default", "") for p in mod.params} if mod else {}
    return _tool_page(target, targets, mod, values)


@bp.post("/tools/run")
def tool_run():
    target, targets = _current_target()
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [request.form.get("target_id", type=int)]).fetchone()
    if not t:
        flash("대상을 먼저 고르세요", "error")
        return redirect(url_for("dash.tools"))
    mod = _tool_modules(t).get(request.form.get("module_id", "")) or abort(404)
    values = {p["name"]: request.form.get(p["name"], p.get("default", "")) for p in mod.params}
    if request.form.get("_drill"):
        # 표에서 '이어서 보기'를 누른 경우 — 그 행이 들고 있던 값으로 덮어쓴다
        try:
            drill = json.loads(request.form["_drill"])
        except ValueError:
            abort(400)
        if not isinstance(drill, dict):
            abort(400)
        values.update({k: str(v) for k, v in drill.items() if k in values})
    request.tool_values = values
    stop = _guard(mod, t, url_for("dash.tools", target=t["id"], tool=mod.id))
    if stop:
        return stop
    try:
        params = _check_types(mod, values)
    except ValueError as e:
        flash(str(e), "error")
        return _tool_page(t, targets, mod, values)

    box = {}

    def call(target_):
        result = mod.run(target_, params)
        if not isinstance(result, ToolResult):
            raise TypeError("도구 모듈의 run() 은 ToolResult 를 돌려줘야 합니다")
        box["result"] = result
        new = sum(_save_finding(mod, t["id"], f) for f in result.findings)
        msg = result.summary + (f" · 결과 {len(result.findings)}건(새로 {new})" if result.findings else "")
        if result.points:
            kept, skipped = _save_points(mod, t["id"], result.points)
            msg += f" · 표면에 {len(result.points) - skipped}개(새로 {kept})"
            if skipped:
                msg += f", 범위 밖 {skipped}개 제외"
        return msg

    _execute(mod, t, params, call)
    return _tool_page(t, targets, mod, values, box.get("result"))


# ── 요청 기록(보낸 요청·받은 응답) ───────────────────────────

STATUS_FILTER = {"2xx": "status BETWEEN 200 AND 299", "3xx": "status BETWEEN 300 AND 399",
                 "4xx": "status BETWEEN 400 AND 499", "5xx": "status >= 500", "err": "status = 0"}


@bp.get("/history")
def history():
    target, targets = _current_target()
    rows = []
    if target:
        sql, args = "SELECT * FROM exchanges WHERE target_id = ?", [target["id"]]
        if request.args.get("run", type=int):
            sql += " AND run_id = ?"
            args.append(request.args.get("run", type=int))
        if request.args.get("module_id"):
            sql += " AND module_id = ?"
            args.append(request.args["module_id"])
        if request.args.get("status") in STATUS_FILTER:
            sql += " AND " + STATUS_FILTER[request.args["status"]]
        if request.args.get("q"):
            sql += " AND (url LIKE ? OR req_body LIKE ?)"
            args += [f"%{request.args['q']}%"] * 2
        rows = get_db().execute(sql + " ORDER BY id DESC LIMIT 300", args).fetchall()
    return render_template("history.html", rows=rows, target=target, targets=targets, args=request.args,
                           modules=_modules_for(target), all_modules=_modules(), status_filter=STATUS_FILTER)


def _raw_request(x):
    s = urlsplit(x["url"])
    lines = [f"{x['method']} {s.path or '/'}{'?' + s.query if s.query else ''} HTTP/1.1", f"Host: {s.netloc}"]
    lines += [f"{k}: {v}" for k, v in json.loads(x["req_headers"])]
    return "\n".join(lines) + "\n\n" + x["req_body"]


def _raw_response(x):
    if x["error"]:
        return f"(응답 없음)\n{x['error']}"
    lines = [f"HTTP/1.1 {x['status']}"] + [f"{k}: {v}" for k, v in json.loads(x["resp_headers"])]
    return "\n".join(lines) + "\n\n" + x["resp_body"]


@bp.get("/history/<int:xid>")
def history_detail(xid):
    db = get_db()
    x = db.execute("SELECT * FROM exchanges WHERE id = ?", [xid]).fetchone() or abort(404)
    target = db.execute("SELECT * FROM targets WHERE id = ?", [x["target_id"]]).fetchone()
    linked = db.execute("SELECT id, title, severity FROM findings WHERE exchange_id = ?", [xid]).fetchall()
    checks = db.execute("SELECT pc.verdict, pc.module_id, p.param, p.place FROM point_checks pc "
                        "JOIN points p ON p.id = pc.point_id WHERE pc.exchange_id = ?", [xid]).fetchall()
    prev = db.execute("SELECT MAX(id) FROM exchanges WHERE run_id = ? AND id < ?", [x["run_id"], xid]).fetchone()[0]
    nxt = db.execute("SELECT MIN(id) FROM exchanges WHERE run_id = ? AND id > ?", [x["run_id"], xid]).fetchone()[0]
    return render_template("history_detail.html", x=x, raw_req=_raw_request(x), raw_resp=_raw_response(x),
                           linked=linked, checks=checks, prev=prev, nxt=nxt, all_modules=_modules(),
                           target=target, targets=_targets())


# ── ATT&CK · 시나리오 · 보고서 ───────────────────────────────

@bp.get("/attack")
def attack():
    target, targets = _current_target()
    hit = set()
    if target:
        hit = {r["technique"] for r in get_db().execute(
            "SELECT DISTINCT technique FROM findings WHERE target_id = ? AND status != 'false_positive'",
            [target["id"]])}
    columns = []
    for tid, en, ko in TACTICS:
        cells = {}
        for mod in _modules_for(target).values():
            for a in mod.attack:
                if a["tactic"] == tid:
                    cell = cells.setdefault(a["technique"], {"technique": a["technique"], "name": a.get("name", ""),
                                                             "modules": [], "hit": a["technique"] in hit,
                                                             "url": technique_url(a["technique"])})
                    cell["modules"].append(mod.name)
        columns.append({"id": tid, "en": en, "ko": ko, "cells": list(cells.values())})
    return render_template("attack.html", columns=columns, target=target, targets=targets)


@bp.get("/scenario")
def scenario():
    target, targets = _current_target()
    steps = []
    if target:
        tech_tactic = _technique_tactic()
        rows = get_db().execute(
            "SELECT * FROM findings WHERE target_id = ? AND status IN ('open', 'confirmed')", [target["id"]]).fetchall()
        groups = {}
        for r in rows:
            tac = tech_tactic.get(r["technique"], "TA0043")
            groups.setdefault(tac, []).append(r)
        for tac in sorted(groups, key=lambda x: TACTIC_ORDER.get(x, 99)):
            steps.append({"tactic": tac, "name": TACTIC_NAME.get(tac, tac), "findings": groups[tac]})
    return render_template("scenario.html", steps=steps, target=target, targets=targets)


@bp.get("/help", endpoint="help")
def help_page():
    target, targets = _current_target()
    mods = _modules().values()
    counts = {"modules": len(mods), "general": sum(1 for m in mods if not m.project),
              "specific": sum(1 for m in mods if m.project), "projects": len(_projects()) - 1}
    return render_template("help.html", counts=counts, target=target, targets=targets)


def _report_rows(tid):
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [tid]).fetchone() or abort(404)
    rows = db.execute(f"SELECT * FROM findings WHERE target_id = ? AND status != 'false_positive' "
                      f"ORDER BY {SEVERITY_ORDER_SQL}, id", [tid]).fetchall()
    exchanges = {}
    for r in rows:
        if r["exchange_id"]:
            x = db.execute("SELECT * FROM exchanges WHERE id = ?", [r["exchange_id"]]).fetchone()
            if x:
                exchanges[r["id"]] = {"request": _raw_request(x), "response": _raw_response(x)[:1500]}
    return t, rows, exchanges


@bp.get("/report/<int:tid>.json")
def report_json(tid):
    """보고서 자동화(도구 ①) 등 다른 도구가 읽을 형식."""
    t, rows, exchanges = _report_rows(tid)
    mods = _modules()
    data = {
        "tool": "vuln-check-dashboard", "version": current_app.jinja_env.globals["VERSION"], "generated_at": now_iso(),
        "target": {"name": t["name"], "url": t["url"], "project": _project_of(t).name,
                   "role": _role_label(t)},
        "findings": [{
            "title": r["title"], "severity": r["severity"], "status": r["status"], "location": r["location"],
            "module": mods[r["module_id"]].name if r["module_id"] in mods else r["module_id"],
            "attack": {"technique": r["technique"], "url": technique_url(r["technique"]) if r["technique"] else ""},
            "evidence": r["evidence"], "recommendation": r["recommendation"],
            "first_seen": r["created_at"], "last_seen": r["last_seen"], "exchange": exchanges.get(r["id"]),
        } for r in rows],
    }
    return Response(json.dumps(data, ensure_ascii=False, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=report_{tid}.json"})


@bp.get("/report/<int:tid>.md")
def report(tid):
    t, rows, exchanges = _report_rows(tid)
    mods = _modules()
    lines = [f"# 점검 결과 — {t['name']}", "", f"- 프로젝트: {_project_of(t).name}",
             f"- 대상: {t['url']}" + (f" ({_role_label(t)})" if _role_label(t) else ""),
             f"- 작성: {fmt_kst(now_iso())} (KST)", f"- 발견: {len(rows)}건", "",
             "| # | 심각도 | 항목 | 위치 | ATT&CK | 상태 |", "|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        lines.append(f"| {i} | {SEVERITY_LABEL[r['severity']]} | {r['title']} | {r['location']} | "
                     f"{r['technique']} | {STATUSES.get(r['status'], r['status'])} |")
    for i, r in enumerate(rows, 1):
        mod = mods.get(r["module_id"])
        lines += ["", f"## {i}. {r['title']}", "",
                  f"- 심각도: {SEVERITY_LABEL[r['severity']]} · 모듈: {mod.name if mod else r['module_id']}",
                  f"- 위치: `{r['location']}`", f"- ATT&CK: [{r['technique']}]({technique_url(r['technique'])})",
                  "", "**근거**", "", "```", r["evidence"], "```", "", "**조치 방안**", "", r["recommendation"]]
        if r["id"] in exchanges:
            x = exchanges[r["id"]]
            lines += ["", "**요청**", "", "```http", x["request"], "```", "", "**응답(앞부분)**", "", "```http",
                      x["response"], "```"]
    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=report_{tid}.md"})
