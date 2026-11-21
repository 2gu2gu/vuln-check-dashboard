import json
import re
import sqlite3
from urllib.parse import quote, urlsplit

from flask import (Blueprint, Response, abort, current_app, flash, g, get_flashed_messages, jsonify, redirect,
                   render_template, request, url_for)

from . import board, campaign, cve, cvss, discovery as dv, grouping, jobs, login as login_mod, mcp as mcp_mod, needs, runfiles, scope, standards, stats, wordlists
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


def _shown(mods):
    """화면에 띄울 모듈만 — 다른 모듈의 부품(hidden)은 뺀다. 실행·검증은 _modules_for 그대로 쓴다."""
    return {k: m for k, m in mods.items() if not m.hidden}


def _modules_for(target):
    """대상이 있으면 범용 + 그 프로젝트 전용 중 역할이 맞는 것, 없으면 전부."""
    return modules_for(_modules(), target["project"], target["role"]) if target else _modules()


def _role_label(t):
    """대상의 역할을 사람이 읽는 이름으로. 터널로 열어 둔 경우 주소만 보고는 어디인지 모른다."""
    if not t or not t["role"]:
        return ""
    return _project_of(t).role_name(t["role"])


def _is_practice(t) -> bool:
    """우리가 띄운 연습용 가짜 서버인가. 점검 대상이 아니다."""
    pj = _projects().get(t["project"]) if t else None
    return bool(pj and pj.is_practice(t["role"]))


def _targets():
    rows = get_db().execute("SELECT * FROM targets ORDER BY project, id").fetchall()
    # 연습용은 뒤로 민다. ?target= 없이 열면 첫 대상이 기본이 되는데, 그게 연습용이면
    # 열자마자 가짜 서버를 보고 있게 된다(지금 실제로 그렇다 — 먼저 등록돼 있다).
    return sorted(rows, key=_is_practice)


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
        "cvss": _rate(r["cvss_vector"] if "cvss_vector" in r.keys() else "",
                      mods.get(r["module_id"])),
    } for r in rows]
    # 위쪽 '점검 현황'(11-20): 보고서 자동화 툴과 같은 그림 세 가지. 연습용은 뺀다
    db = get_db()
    real = [t for t in targets if not _is_practice(t)]
    charts = stats.overview(db, real) if target else None
    act = stats.activity(db, real) if target else None
    bd = stats.breakdown(db, real, _modules()) if target else None
    cal = stats.calendar(db, real, _project_of(target).schedule) if target else None
    return render_template("results.html", target=target, targets=targets, findings=data, charts=charts,
                           act=act, bd=bd, cal=cal,
                           counts=counts, modules=_modules_for(target), severities=SEVERITIES,
                           args=request.args, cvss_metrics=cvss.METRICS)


def _rate(vector, mod=None):
    """저장된 벡터를 화면에 쓸 모양으로. 없으면 모듈이 적어 둔 기본 벡터를 '제안'으로 돌려준다."""
    for text, saved in ((vector, True), (getattr(mod, "cvss", "") if mod else "", False)):
        if text:
            try:
                return {**cvss.rate(text), "saved": saved}
            except cvss.BadVector:
                continue
    return None


@bp.post("/findings/purge-false")
def findings_purge_false():
    """오탐으로 표시한 결과를 지운다.

    틀린 줄을 표시만 해 두면 표가 계속 그만큼 길어지고, 보고서에 쓸 때마다 다시 걸러야 한다.
    왜 틀렸는지는 모듈 코드와 테스트에 남아 있으니(11-21 의 SPA 껍데기 건들이 그랬다) 표에서는
    치운다. 지우는 것은 **오탐으로 표시한 것만** 이다.
    """
    tid = request.form.get("target_id", type=int)
    db = get_db()
    where, args = "status = 'false_positive'", []
    if tid:
        where += " AND target_id = ?"
        args = [tid]
    n = db.execute(f"SELECT COUNT(*) FROM findings WHERE {where}", args).fetchone()[0]
    db.execute(f"DELETE FROM findings WHERE {where}", args)
    db.commit()
    flash(f"오탐으로 표시한 결과 {n}건을 지웠습니다" if n else "지울 오탐이 없습니다", "ok")
    return redirect(request.form.get("back") or url_for("dash.results", target=tid or None))


@bp.post("/findings/<int:fid>/status")
def finding_status(fid):
    status = request.form.get("status")
    if status not in STATUSES:
        abort(400)
    db = get_db()
    row = db.execute("SELECT target_id FROM findings WHERE id = ?", [fid]).fetchone()
    if not row:
        abort(404)

    # CVSS 를 같이 보냈으면 벡터로 만들어 저장하고, 심각도를 그 점수에서 다시 매긴다.
    # 벡터와 등급이 따로 놀면 보고서에서 둘이 어긋난다(노션에서 실제로 그랬다).
    sets, args = ["status = ?"], [status]
    if request.form.get("cvss") == "clear":
        sets += ["cvss_vector = ?"]
        args += [""]
    elif any(request.form.get(f"cvss_{k}") for k in cvss.ORDER):
        try:
            rated = cvss.rate({k: request.form.get(f"cvss_{k}", "") for k in cvss.ORDER})
        except cvss.BadVector as e:
            flash(f"CVSS: {e}", "error")
            return redirect(url_for("dash.results", target=row["target_id"]))
        sets += ["cvss_vector = ?", "severity = ?"]
        args += [rated["vector"], rated["severity"]]

    db.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id = ?", [*args, fid])
    db.commit()
    return redirect(url_for("dash.results", target=row["target_id"]))


@bp.get("/cvss")
def cvss_score():
    """고르는 칸이 바뀔 때마다 점수를 물어보는 자리.

    계산식을 JS 로 복사하면 언젠가 서버와 어긋난다. 한 군데서만 센다.
    """
    try:
        return cvss.rate({k: request.args.get(k, "") for k in cvss.ORDER})
    except cvss.BadVector as e:
        return {"error": str(e)}, 400


def _with_result_links(rows):
    """끝난 도구 실행에는 결과 표를 다시 여는 주소를 붙인다(토스트·드로어)."""
    for j in rows:
        if j.get("stage") == "tool" and j["status"] == "done":
            j["result_url"] = url_for("dash.tools", target=j["target_id"], tool=j["module_id"], run=j["run_id"])
    return rows


@bp.app_context_processor
def _jobs_for_page():
    """모든 화면이 '도는 중'과 '막 끝난 것'을 볼 수 있게.

    백그라운드 작업자는 flash 를 못 쓴다(요청이 없다). 그래서 끝난 결과 문구도
    여기로 흘려보낸다 — 안 그러면 "지점 3개 수집" 같은 말이 어디에도 안 남는다.
    """
    try:
        tid = request.args.get("target", type=int)
    except RuntimeError:          # 요청 밖에서 렌더할 때
        tid = None
    return {"job_toasts": _with_result_links(jobs.take_announcements(tid)),
            "job_live": jobs.live_count(),
            "job_max": jobs.MAX_LIVE}


@bp.get("/jobs")
def jobs_list():
    """우측 드로어가 물어보는 자리. 도는 것이 위, 그 아래 최근 끝난 것.

    done 은 막 끝나 아직 안 알린 것 — 화면을 새로 그리지 않아도 끝났다는 알림이 뜨게(11-20).
    """
    target = request.args.get("target", type=int)
    return {"jobs": _with_result_links(jobs.listing(target)), "live": jobs.live_count(), "max": jobs.MAX_LIVE,
            "done": _with_result_links(jobs.take_announcements(target))}


@bp.after_request
def _stay_on_page(resp):
    """실행을 화면에서 fetch 로 보냈으면 페이지를 넘기지 않는다(사용자 결정 11-20).

    모듈을 돌릴 때마다 화면이 새로 그려지고, 고른 값이 초기화되고, 결과 탭으로 넘어갔다.
    라우트는 그대로 두고 — 넘길 곳(redirect)과 남길 말(flash)을 그대로 쓴다 — fetch 로 온 POST 의
    redirect 만 JSON 으로 바꿔 돌려준다. 화면은 그 말을 알림으로 띄우고 제자리에 있는다.
    """
    if (request.method == "POST" and request.headers.get("X-Requested-With") == "fetch"
            and 300 <= resp.status_code < 400):
        msgs = [{"category": c, "message": m} for c, m in get_flashed_messages(with_categories=True)]
        return jsonify({"ok": not any(x["category"] == "error" for x in msgs), "messages": msgs,
                        "location": resp.headers.get("Location", "")})
    return resp


@bp.post("/jobs/<int:run_id>/cancel")
def job_cancel(run_id):
    """멈춤. 이미 나간 요청은 돌아올 때까지 기다린다 — 서버에는 이미 닿았다."""
    if not jobs.cancel(run_id):
        return {"ok": False, "why": "이미 끝났거나 없는 실행입니다"}, 404
    return {"ok": True}


@bp.get("/jobs/exchange/<int:xid>")
def job_exchange_raw(xid):
    """터미널 화면에서 한 줄을 누르면 그 **패킷 원문**을 그 자리에 편다.

    요청 기록 탭으로 넘어가면 보던 흐름을 잃는다. 돌고 있는 것을 보는 중이라면 더 그렇다.
    """
    x = get_db().execute("SELECT * FROM exchanges WHERE id = ?", [xid]).fetchone() or abort(404)
    return {"id": xid, "request": _raw_request(x), "response": _raw_response(x),
            "ms": x["ms"], "size": x["size"], "error": x["error"] or ""}


@bp.get("/jobs/<int:run_id>/exchanges")
def job_exchanges(run_id):
    """그 실행이 지금까지 보낸 요청. 드로어에서 눌러 들어가면 실시간으로 쌓인다."""
    after = request.args.get("after", 0, type=int)
    rows = get_db().execute(
        "SELECT id, method, url, status, size, ms, error, created_at FROM exchanges "
        "WHERE run_id = ? AND id > ? ORDER BY id LIMIT 200", [run_id, after]).fetchall()
    job = jobs.get(run_id)
    return {"exchanges": [dict(r) for r in rows], "live": bool(job and job.live)}


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
                raise ValueError(f"점검 대상을 골라 주세요 ({', '.join(project.roles)})")
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
    logins = {row["id"]: login_mod.config_for(_projects().get(row["project"]), row["role"])
              for row in targets}
    # 지금 들어 있는 값을 그대로 넘긴다 — 토큰을 확인하고 복사할 수 있어야 한다.
    # 빈 칸으로 두면 편집하다가 모르고 지우는 일도 생긴다.
    header_text = {row["id"]: (row["headers"] or "") for row in targets}
    # 표면 탭을 여기로 합쳤다(11-20 사용자 결정). 대상을 누르면 그 대상이 모은
    # 페이지·파라미터와 지점 점검이 목록 아래에 뜬다.
    # ?target= 로 누른 대상만 펼친다. 처음 열면 목록만 보인다.
    picked = target if request.args.get("target", type=int) and target else None
    show_all = request.args.get("show") == "all"
    groups, totals = _surface_of(picked, sort=request.args.get("sort", ""), state=request.args.get("state", ""),
                                 show_all=show_all)
    # 고를 파라미터가 전부 '없는 경로' 안에 있으면 숨긴 채로는 아무것도 못 고른다(11-20 사용자 지적).
    # 안내만 띄우고 한 번 더 누르게 하지 말고, 그런 대상에서는 처음부터 펴서 보여 준다.
    if not show_all and not totals["shown_params"] and totals["hidden_params"]:
        show_all = True
        groups, totals = _surface_of(picked, sort=request.args.get("sort", ""),
                                     state=request.args.get("state", ""), show_all=True)
        totals["opened_for_params"] = True
    if picked:
        totals["shadow_prefix"], shadow = shadow_points(picked["id"])
        totals["shadow"] = len(shadow)
    point_counts = {row["target_id"]: {"pages": row["pages"], "params": row["params"]} for row in get_db().execute(
        "SELECT target_id, COUNT(DISTINCT CASE WHEN state NOT IN ('not_found', 'soft_404') THEN url END) AS pages, "
        "SUM(param != '') AS params FROM points GROUP BY target_id")}
    return render_template("targets.html", target=target, targets=targets, picked=picked, point_counts=point_counts,
                           header_names=names, header_text=header_text, logins=logins,
                           auth_ways=login_mod.AUTH_WAYS,
                           groups=groups, totals=totals, probes=_shown(_probe_modules(target)),
                           collectors=[m for m in _shown(_modules_for(target)).values() if m.stage == "collect"],
                           verdicts=VERDICTS, states=dv.STATES, source_label=dv.SOURCE_LABEL, args=request.args,
                           surl=_surface_link(target))


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


@bp.post("/targets/<int:tid>/auth")
def target_auth(tid):
    """손으로 넣는 인증(Bearer·쿠키·Basic·API 키) — 고른 방식대로 헤더 한 줄을 만들어 넣는다."""
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [tid]).fetchone() or abort(404)
    back = url_for("dash.targets", target=tid)
    try:
        name, line = login_mod.auth_line(request.form.get("way", ""), request.form)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(back)
    db.execute("UPDATE targets SET headers = ? WHERE id = ?",
               [login_mod.replace_line(t["headers"], name, line), tid])
    db.commit()
    # 값은 가리지 않는다 — 자체 실습 환경이고, 안 보이면 맞게 들어갔는지 확인할 수 없다(요청 기록도 같은 기준)
    flash(f"인증 헤더에 넣었습니다 — {line}", "ok")
    return redirect(back)


@bp.post("/targets/<int:tid>/login")
def target_login(tid):
    """로그인해서 토큰을 받아 이 대상의 인증 헤더에 넣는다. 비밀번호는 저장하지 않는다."""
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [tid]).fetchone() or abort(404)
    back = url_for("dash.targets", target=tid)
    cfg = login_mod.config_for(_projects().get(t["project"]), t["role"])
    if not cfg:
        flash("이 대상에는 로그인 방법이 정해져 있지 않습니다", "error")
        return redirect(back)

    hosts = _project_of(t).role_scope(t["role"])
    try:
        g.scope_hosts = hosts
        token = login_mod.fetch_token(t["url"], cfg, request.form.get("ident", "").strip(),
                                      request.form.get("secret", ""), hosts=hosts)
    except (login_mod.LoginFailed, scope.OutOfScope, OSError) as e:
        flash(str(e), "error")
        return redirect(back)
    finally:
        g.pop("scope_hosts", None)

    # 이미 있던 헤더는 두고 인증 줄만 바꾼다
    name = (cfg.get("header") or "Authorization").lower()
    keep = [ln for ln in (t["headers"] or "").splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip().lower() != name]
    text = "\n".join(keep + [login_mod.header_line(cfg, token)])
    db.execute("UPDATE targets SET headers = ? WHERE id = ?", [text, tid])
    db.commit()
    # 토큰을 그대로 보여 준다. 자체 실습 환경이고 받자마자 curl 에 붙여 쓰는 일이 많다.
    # 가려 두면 '맞게 들어갔나' 를 확인할 수도, 복사해 쓸 수도 없다.
    flash("로그인했습니다. 인증 헤더에 넣었습니다 — %s  (비밀번호는 저장하지 않았습니다)"
          % login_mod.header_line(cfg, token), "ok")
    return redirect(back)


# ── 모듈 ──────────────────────────────────────────────────────

@bp.get("/modules")
def modules():
    target, targets = _current_target()
    available = _shown(_modules_for(target))
    project = _project_of(target) if target else None
    # 묶는 기준은 취약점 하나만 둔다(11-20 사용자 결정). 단계·전술·분야 탭은 뺐다.
    way = "vuln"
    rows = grouping.group(list(available.values()), way)
    runs = get_db().execute(
        "SELECT runs.*, targets.name AS target_name, "
        "(SELECT COUNT(*) FROM findings f WHERE f.run_id = runs.id) AS n, "
        "(SELECT COUNT(*) FROM exchanges x WHERE x.run_id = runs.id) AS reqs, "
        "targets.project AS target_project, targets.role AS target_role "
        "FROM runs JOIN targets ON targets.id = runs.target_id ORDER BY runs.id DESC LIMIT 15").fetchall()
    return render_template("modules.html", rows=rows, all_modules=_modules(), project=project,
                           hidden=len(_modules()) - len(available), errors=current_app.config["MODULE_ERRORS"],
                           target=target, targets=targets, runs=runs, tactic_name=TACTIC_NAME,
                           missing=grouping.empty_groups(way, rows), total=len(available))


def module_needs(mod, t=None):
    """이 모듈이 미리 준비해야 하는 것 + 지금 준비됐는지. 화면에서도 쓴다."""
    header_names = list(_parse_headers(t["headers"])) if t and t["headers"] else []
    return needs.check(mod, header_names)


def _guard(mod, t, back):
    """실행 전 확인. 문제가 있으면 돌아갈 redirect, 없으면 None.

    실행마다 '자체 환경 확인' 을 누르게 하던 것은 뺐다(11-21 사용자 지시). 범위를 지키는 것은
    체크박스가 아니라 `core.fetch` 의 `scope.ensure_in_scope` 다 — 범위 밖 주소는 애초에 요청이
    나가지 않는다. 사람이 매번 같은 칸을 누르는 것은 그 위에 얹힌 문턱이었을 뿐이다.
    """
    if mod.project not in ("", t["project"]):
        flash(f"{mod.name} 은 {_projects()[mod.project].name} 전용 모듈입니다", "error")
        return redirect(back)
    blocked = _need_block(mod, t)
    if blocked:
        flash(blocked, "error")
        return redirect(back)
    return None


def _need_block(mod, t):
    """돌리기 전에 없으면 안 되는 것 — 있으면 사람이 읽을 한 줄, 없으면 ''.

    화면과 MCP 가 **같은 문턱**을 보게 한 자리다(11-21 화이트박스 점검). MCP 쪽에만 이 검사가
    없었다 — 토큰이 있어야 도는 모듈이 토큰 없이 돌아 '다 막혀 있다' 는 거짓 결과를 냈다.
    """
    missing = needs.blocking(mod, list(_parse_headers(t["headers"])) if t["headers"] else [])
    if not missing:
        return ""
    n = missing[0]
    return f"{mod.name} 은 {n['label']}{(' ' + n['name']) if n['name'] else ''} 가 있어야 돌아갑니다 — {n['how']}"


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


CACHEABLE = (str, int, float, bytes, type(None))


def _save_cache(tid, mid, cache):
    """모듈이 남긴 고를 저장한다. 고는 **빠르게 하자는 것** 이지 결과가 아니다 —
    모듈이 글자가 아닌 것을 넣어 두었으면 그 줄만 버린다. 11-21 에 튜플 열쇠 하나가
    이미 끝난 실행의 결과까지 통째로 날렸다(sqlite 가 묶음을 거부한다)."""
    db, now = get_db(), now_iso()
    rows = [(tid, mid, k, v, now) for k, v in cache.items()
            if isinstance(k, str) and isinstance(v, CACHEABLE)]
    if len(rows) != len(cache):
        current_app.logger.warning("tool_cache: 저장할 수 없는 항목 %d개를 건너뜀 (%s)", len(cache) - len(rows), mid)
    db.executemany("INSERT INTO tool_cache (target_id, module_id, key, value, created_at) VALUES (?,?,?,?,?) "
                   "ON CONFLICT (target_id, module_id, key) DO UPDATE SET value = excluded.value", rows)
    db.commit()


def _setup_run(mod, t, run_id, stop_check=None):
    """이 실행이 쓸 범위·요청 설정을 지금 컨텍스트(g)에 깐다.

    요청 안에서 돌든 작업자 스레드에서 돌든 같은 자리에 같은 것을 둔다 —
    `g` 는 app_context 마다 따로라 스레드끼리 섞이지 않는다.
    """
    cfg = current_app.config
    g.run_id = run_id
    # 실행 중 core.fetch 는 이 범위로만 나간다 — 역할을 골랐으면 그 서버의 포트까지
    g.scope_hosts = _project_of(t).role_scope(t["role"])
    # 포트를 가리지 않는 일(포트 스캔)은 프로젝트 호스트 목록으로만 검사한다
    g.host_scope = _project_of(t).scope
    g.run_ctx = RunContext(t["url"], _parse_headers(t["headers"]), cfg["DELAY_MS"], cfg["MAX_REQUESTS"],
                           _recorder(t["id"], mod.id), cache=_load_cache(t["id"], mod.id),
                           stop_check=stop_check)
    return g.run_ctx


def _finish_run(mod, t, run_id, status, msg="", err=""):
    """실행 기록을 닫고, 중간까지 읽은 값을 남긴다."""
    db = get_db()
    ctx = g.get("run_ctx")
    db.execute("UPDATE runs SET status = ?, error = ?, message = ?, sent = ?, finished_at = ? WHERE id = ?",
               [status, err, msg, getattr(ctx, "count", 0), now_iso(), run_id])
    db.commit()
    if ctx is not None:
        # 중간에 멈춰도 그때까지 읽은 값은 남겨 둔다
        _save_cache(t["id"], mod.id, ctx.cache)
    g.pop("scope_hosts", None)
    g.pop("host_scope", None)
    g.pop("run_ctx", None)


def _new_run(mod, t, params):
    db = get_db()
    cur = db.execute("INSERT INTO runs (target_id, module_id, params, status, started_at) VALUES (?, ?, ?, 'running', ?)",
                     [t["id"], mod.id, json.dumps(params, ensure_ascii=False), now_iso()])
    db.commit()
    return cur.lastrowid


def _execute_bg(mod, t, params, call):
    """뒤에서 돌린다. 바로 돌아오고, 진행은 우측 드로어에서 본다.

    같은 서버를 여러 모듈이 동시에 때리면 요청 간격을 지켜도 합쳐진 양은 그만큼
    늘어난다. 공유 서버라 그게 제일 위험해서 동시 실행 수에 상한을 둔다.
    """
    if jobs.live_count() >= jobs.MAX_LIVE:
        flash(f"지금 {jobs.MAX_LIVE}개가 돌고 있습니다. 하나가 끝나면 다시 눌러 주세요", "error")
        return None
    run_id = _new_run(mod, t, params)
    app = current_app._get_current_object()

    def work(job):
        job.ctx = _setup_run(mod, t, run_id, stop_check=job.should_stop)
        try:
            scope.ensure_in_scope(t["url"])
            msg = call(Target(t["id"], t["name"], t["url"]))
            _finish_run(mod, t, run_id, "cancelled" if job._stop.is_set() else "done", msg)
            return msg
        except jobs.Cancelled as e:
            get_db().rollback()
            _finish_run(mod, t, run_id, "cancelled", err=str(e))
            raise
        except Exception as e:  # noqa: BLE001
            get_db().rollback()
            _finish_run(mod, t, run_id, "error", err=str(e))
            raise

    jobs.start(app, run_id, t, mod, work)
    flash(f"{mod.name} 을 뒤에서 돌리고 있습니다 — 오른쪽 '도는 중' 에서 진행을 봅니다", "ok")
    return run_id


REPLAY = "다시 보낼 요청"


def _replay_line(xid):
    """근거 끝에 붙일 **그대로 다시 보낼 수 있는 요청 한 줄**.

    자리표시자(`file=<double-full>`)만 적혀 있으면 사람도 도구도 돌려 볼 수 없다 — 11-21 에
    결과 246건을 재현할 때 민감 파일 11건이 이것 때문에 재현 불가였다. 보낸 요청은 요청 기록에
    이미 남아 있으니, 그 한 줄을 근거로 끌어올린다.
    """
    if not xid:
        return ""
    row = get_db().execute("SELECT method, url, req_body FROM exchanges WHERE id = ?", [xid]).fetchone()
    if not row:
        return ""
    line = f"{REPLAY}: {row['method']} {row['url']}"
    if row["req_body"]:
        line += "\n  본문: " + row["req_body"][:300]
    return line


def _save_finding(mod, tid, f):
    """같은 대상·모듈·제목·위치면 새로 쌓지 않고 갱신한다. 조치됨이었는데 다시 나오면 미확인으로 되돌린다(재발)."""
    db, now = get_db(), now_iso()
    tech = f.technique or mod.attack[0]["technique"]
    xid = getattr(f.response, "exchange_id", 0) or None
    line = _replay_line(xid)
    if line and REPLAY not in (f.evidence or ""):
        f.evidence = (f.evidence or "").rstrip() + "\n\n" + line
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
        # 상태·점수는 새로 확인한 값이 있을 때만 덮는다 — 확인 없이 다시 모은 모듈이 지우지 않게
        db.execute(
            "INSERT INTO points (target_id, method, url, param, place, sample, source, module_id, first_seen, last_seen, "
            "state, status, evidence, risk) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (target_id, method, url, param, place) DO UPDATE SET "
            "last_seen = excluded.last_seen, sample = CASE WHEN excluded.sample != '' THEN excluded.sample ELSE sample END, "
            "state = CASE WHEN excluded.state != '' THEN excluded.state ELSE state END, "
            "status = CASE WHEN excluded.state != '' THEN excluded.status ELSE status END, "
            "evidence = CASE WHEN excluded.evidence != '' THEN excluded.evidence ELSE evidence END, "
            "risk = CASE WHEN excluded.state != '' THEN excluded.risk ELSE risk END",
            [tid, p.method, p.url, p.param, p.place, sample, p.source, mod.id, now, now,
             p.state, p.status, p.evidence[:1000], p.risk])
        new += not exists
    return new, skipped


def _back(default):
    """폼이 'back' 을 실어 보냈으면 그리로 돌아간다(모듈 팝업 → 같은 팝업). 이 서버 안 경로만 받는다."""
    b = request.form.get("back", "")
    return b if b.startswith("/") and not b.startswith("//") else default


@bp.post("/modules/<mid>/run")
def module_run(mid):
    mod = _modules().get(mid) or abort(404)
    t = get_db().execute("SELECT * FROM targets WHERE id = ?", [request.form.get("target_id", type=int)]).fetchone()
    if not t:
        flash("대상을 먼저 고르세요", "error")
        return redirect(url_for("dash.modules"))
    if mod.stage == "probe":
        flash(f"{mod.name} 은 지점 점검 모듈입니다. 대상 탭에서 지점을 골라 실행하세요", "error")
        return redirect(_surface_url(t["id"]))
    if mod.stage == "tool":
        # 도구도 다른 모듈처럼 이 화면에서 바로 뒤로 보낸다. 결과 표는 끝난 뒤
        # 도구 탭에서 연다(드로어·토스트에서 이어지는 링크).
        back = _back(url_for("dash.modules", target=t["id"]))
        stop = _guard(mod, t, back)
        if stop:
            return stop
        values = {p["name"]: request.form.get(p["name"], p.get("default", "")) for p in mod.params}
        pid = request.form.get("point", type=int)
        if mod.takes_point and pid:
            # 팝업에서 고른 지점 하나 — 그 주소·파라미터로 때린다(심화 모듈, 11-20)
            row = get_db().execute("SELECT * FROM points WHERE id = ? AND target_id = ? AND param != ''",
                                   [pid, t["id"]]).fetchone()
            if not row:
                flash("고른 지점을 찾지 못했습니다", "error")
                return redirect(back)
            values.update(point_url=row["url"], point_param=row["param"], point_place=row["place"],
                          point_sample=row["sample"])
        try:
            params = _check_types(mod, values)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(back)
        _execute_bg(mod, t, params, _tool_call(mod, t, params))
        return redirect(back)
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
        _execute_bg(mod, t, params, call)
        return redirect(_back(_surface_url(t["id"])))

    def call(target):
        results = mod.run(target, params) or []
        for f in results:
            if not isinstance(f, Finding):
                raise TypeError("run() 은 Finding 목록을 돌려줘야 합니다")
        new = sum(_save_finding(mod, t["id"], f) for f in results)
        return f"{len(results)}건 발견(새로 {new})"
    _execute_bg(mod, t, params, call)
    return redirect(_back(url_for("dash.results", target=t["id"])))


# ── 모듈 팝업(11-20 사용자 결정) ─────────────────────────────────
# 모듈은 취약점별로 수집한 지점에 '전부 때리는' 구조다. 모듈을 누르면 팝업이 떠서 왼쪽에 그 모듈의
# 설정·실행, 오른쪽에 이 대상이 모은 지점 표가 나온다. 지점 점검 모듈은 거기서 지점을 골라 바로 돌린다.
# 팝업 안의 폼은 back 으로 '같은 팝업이 열린 모듈 화면' 을 실어 보내 실행 뒤 그 자리로 돌아온다.

@bp.get("/modules/<mid>/panel")
def module_panel(mid):
    target, targets = _current_target()
    mod = _modules_for(target).get(mid) if target else _modules().get(mid)
    if not mod:
        abort(404)
    groups, totals = _surface_of(target, show_all=True) if (target and (mod.stage == "probe" or mod.takes_point)) else ([], {})
    back = url_for("dash.modules", target=target["id"] if target else None, open=mid)
    return render_template("module_panel.html", mod=mod, target=target, groups=groups, totals=totals,
                           verdicts=VERDICTS, source_label=dv.SOURCE_LABEL, tactic_name=TACTIC_NAME, back=back,
                           partial=request.args.get("partial") == "1", targets=targets)


# ── 표면(수집된 지점) — 화면은 대상 탭 아래 ─────────────────────────────────────────

def _probe_modules(target):
    return {k: m for k, m in _modules_for(target).items() if m.stage == "probe"}


MISSING = ("not_found", "soft_404")


def _suggest_modules(target):
    """추천 점검 키 → 이 대상에서 쓸 수 있는 모듈 [(id, 이름, 단계)]. 없으면 빈 목록."""
    mods = _shown(_modules_for(target)).values()
    want = {"INJECT": lambda m: m.stage == "probe" and (getattr(m, "vuln", "") in ("XSS", "SQL") or m.id == "payload_probe"),
            "FILE": lambda m: getattr(m, "vuln", "") == "FILE" and m.stage in ("probe", "tool")}
    return {k: [(m.id, m.name, m.stage) for m in mods if f(m)] for k, f in want.items()}


def _evidence(text):
    try:
        ev = json.loads(text or "")
        return ev if isinstance(ev, dict) else None
    except ValueError:
        return None


def _surface_of(target, sort="", state="", show_all=False):
    """대상 하나가 모은 지점을 주소별로 묶는다 → (묶음 목록, 개수).

    표면 자동 수집이 남긴 상태·점수·근거를 묶음마다 붙이고(11-20 2단계), 고른 대로 거르고 줄 세운다.
    없는 경로(404·가짜 200)는 기본으로 숨긴다 — 보이면 '찔러 볼 곳' 처럼 읽힌다.
    """
    groups, totals = [], {"endpoints": 0, "params": 0, "shown_params": 0, "hidden": 0, "hidden_params": 0,
                          **{v: 0 for v in VERDICTS}}
    if not target:
        return groups, totals
    suggest_mods = _suggest_modules(target)
    db = get_db()
    checks = {}
    for c in db.execute("SELECT pc.* FROM point_checks pc JOIN points p ON p.id = pc.point_id WHERE p.target_id = ?",
                        [target["id"]]):
        checks.setdefault(c["point_id"], []).append(c)
    by_url = {}
    for p in db.execute("SELECT * FROM points WHERE target_id = ? ORDER BY url, method, place, param", [target["id"]]):
        grp = by_url.setdefault(p["url"], {"url": p["url"], "path": urlsplit(p["url"]).path or "/",
                                           "methods": set(), "sources": set(), "params": [], "ends": [], "risk": 0,
                                           "any_id": p["id"], "checks": []})
        grp["methods"].add(p["method"])
        grp["sources"].update(s for s in p["source"].split(",") if s)
        grp["risk"] = max(grp["risk"], p["risk"] or 0)
        if not p["param"]:
            # 주소 단위 점검(보안 헤더·정보 노출)의 판정은 파라미터 없는 줄에 붙는다
            grp["checks"] += [{"module": _modules()[c["module_id"]].name if c["module_id"] in _modules() else c["module_id"],
                               "verdict": c["verdict"], "evidence": c["evidence"], "exchange_id": c["exchange_id"]}
                              for c in checks.get(p["id"], [])]
            if p["state"]:
                grp["ends"].append({"method": p["method"], "state": p["state"], "status": p["status"],
                                    "risk": p["risk"], "ev": _evidence(p["evidence"])})
            continue
        grp["params"].append({**dict(p), "suggest": [
            {"key": k, "label": dv.SUGGEST_LABEL[k], "modules": suggest_mods.get(k, [])}
            for k in dv.suggest(p["param"], p["place"])], "checks": [
            {"module": _modules()[c["module_id"]].name if c["module_id"] in _modules() else c["module_id"],
             "verdict": c["verdict"], "evidence": c["evidence"], "exchange_id": c["exchange_id"]}
            for c in checks.get(p["id"], [])]})
        totals["params"] += 1
        for c in checks.get(p["id"], []):
            totals[c["verdict"]] += 1
    groups = list(by_url.values())
    keep = []
    for gr in groups:
        states = {e["state"] for e in gr["ends"]}
        gr["missing"] = bool(states) and states <= set(MISSING)
        # 엔드포인트 수는 있는 주소만 센다 — 없는 경로(404·가짜 200)까지 세면 '30개인데 파라미터 9개' 처럼
        # 부풀어 보였다(사용자 지적 11-20). 숨긴 수는 hidden 으로 따로 보인다
        if not gr["missing"]:
            totals["endpoints"] += 1
        if state and state not in states:
            continue
        if gr["missing"] and not show_all and state not in MISSING:
            totals["hidden"] += 1
            totals["hidden_params"] = totals.get("hidden_params", 0) + len(gr["params"])
            continue
        keep.append(gr)
    # 화면에 실제로 보이는(= 고를 수 있는) 파라미터 수. totals["params"] 는 숨긴 것까지 센 전체다
    totals["shown_params"] = sum(len(gr["params"]) for gr in keep)
    totals["states"] = sorted({e["state"] for gr in groups for e in gr["ends"]}, key=list(dv.STATES).index)
    if sort == "risk" or (not sort and any(gr["risk"] for gr in keep)):
        keep.sort(key=lambda gr: (-gr["risk"], gr["path"]))
    return keep, totals


def _surface_link(target):
    """지금 고른 거르기 값을 지키며 하나만 바꾼 대상 탭 주소를 만든다(빈 값은 뺀다)."""
    def link(over):
        keep = {k: v for k, v in request.args.items() if k != "target"}
        keep.update(over)
        return url_for("dash.targets", target=target["id"] if target else None,
                       **{k: v for k, v in keep.items() if v}) + "#surface"
    return link


def _surface_url(tid):
    return url_for("dash.targets", target=tid) + "#surface"


@bp.get("/surface")
def surface():
    """옛 표면 탭 주소. 즐겨찾기·옛 링크가 끊기지 않게 대상 탭의 그 자리로 보낸다."""
    tid = request.args.get("target", type=int)
    return redirect(_surface_url(tid) if tid else url_for("dash.targets") + "#surface")


@bp.post("/surface/probe")
def surface_probe():
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [request.form.get("target_id", type=int)]).fetchone() or abort(404)
    back = _back(_surface_url(t["id"]))
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

    points = _probe_points(t, mod, ids)
    _execute_bg(mod, t, {**params, "points": len(points)}, _probe_call(mod, t, points, params))
    return redirect(back)


def _probe_points(t, mod, ids):
    """고른 지점 id 들 → 모듈에 넘길 Point 목록. 주소 단위 모듈은 주소마다 한 줄로 묶는다."""
    db = get_db()
    marks = ",".join("?" * len(ids))
    points = []
    if mod.unit == "endpoint":
        # 주소 하나에 한 번. 판정은 그 주소의 파라미터 없는 줄(GET)에 남긴다 — 없으면 만든다
        urls = sorted({r["url"] for r in db.execute(f"SELECT url FROM points WHERE target_id = ? AND id IN ({marks})",
                                                      [t["id"], *ids])})
        for url in urls:
            db.execute("INSERT OR IGNORE INTO points (target_id, method, url, param, place, source, module_id, first_seen, last_seen) "
                       "VALUES (?, 'GET', ?, '', 'path', '', ?, ?, ?)", [t["id"], url, mod.id, now_iso(), now_iso()])
            pid = db.execute("SELECT id FROM points WHERE target_id = ? AND method = 'GET' AND url = ? AND param = '' AND place = 'path'",
                             [t["id"], url]).fetchone()["id"]
            points.append(Point(method="GET", url=url, param="", place="path", id=pid))
        db.commit()
    rows = [] if mod.unit == "endpoint" else db.execute(
        f"SELECT * FROM points WHERE target_id = ? AND param != '' AND id IN ({marks})", [t["id"], *ids]).fetchall()
    for r in rows:
        siblings = db.execute("SELECT param, sample FROM points WHERE target_id = ? AND url = ? AND method = ? AND place = ? "
                              "AND param != ''", [t["id"], r["url"], r["method"], r["place"]])
        points.append(Point(method=r["method"], url=r["url"], param=r["param"], place=r["place"], sample=r["sample"],
                            source=r["source"], id=r["id"], fields={s["param"]: s["sample"] for s in siblings}))
    return points


def _probe_call(mod, t, points, params):
    """지점 점검 모듈을 돌리고 판정을 적는 일 — `_execute_bg` 에 넘길 함수를 만든다."""
    def call(target):
        # 작업자 스레드에서 돌 수 있으므로 연결을 여기서 다시 받는다.
        # 바깥 db 는 요청 스레드 것이라 sqlite 가 거부한다.
        db = get_db()
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
                    location=f"{p.url} ({p.place}: {p.param})" if p.param else p.url,
                    recommendation=c.recommendation, response=c.response))
        skipped = len(points) - len(checks)
        return (f"지점 {len(checks)}개 — " + " · ".join(f"{VERDICTS[v]} {n}" for v, n in counts.items())
                + (f", 건너뜀 {skipped}" if skipped else ""))
    return call


SHADOW_MIN = 5  # 이만큼 겹쳐야 '접두사를 빼먹은 것' 으로 본다 — 우연히 비슷한 주소 몇 개로는 안 지운다


def shadow_points(tid):
    """같은 API 가 접두사만 다르게 두 벌 들어온 것 → (접두사, 지울 지점 id 들).

    명세의 servers 가 실제 접두사를 빼먹으면(새싹에듀는 `/backend`) 자동 수집이 **닿지 않는
    주소** 를 등록한다. 그 주소는 화면 틀(SPA 껍데기)만 돌려줘 점검이 헛돈다 — 11-21 에
    사용자 웹에서 44개가 그랬고, 거짓 양성이 줄줄이 나온 뿌리였다.

    지우는 것은 **명세에서 온 것만** 이다. 링크·JS 로도 찾은 주소는 진짜 화면이라 그대로 둔다.
    """
    rows = get_db().execute("SELECT id, url, source FROM points WHERE target_id = ?", [tid]).fetchall()
    paths = {urlsplit(r["url"]).path for r in rows}
    best, best_n = "", 0
    for p in paths:
        head = p.strip("/").split("/")[0]
        if not head:
            continue
        pre = "/" + head
        n = sum(1 for q in paths if q.startswith(pre + "/") and q[len(pre):] in paths)
        if n > best_n:
            best, best_n = pre, n
    if best_n < SHADOW_MIN:
        return "", []
    doomed = [r["id"] for r in rows
              if r["source"] == "spec" and best + urlsplit(r["url"]).path in paths]
    return best, doomed


@bp.post("/surface/dedupe")
def surface_dedupe():
    """접두사를 빼먹어 두 벌이 된 주소 중 닿지 않는 쪽을 지운다."""
    tid = request.form.get("target_id", type=int)
    pre, doomed = shadow_points(tid)
    if not doomed:
        flash("겹치는 주소가 없습니다", "ok")
        return redirect(_surface_url(tid))
    db = get_db()
    db.executemany("DELETE FROM points WHERE id = ?", [(i,) for i in doomed])
    db.commit()
    flash(f"{pre} 가 빠진 같은 주소 {len(doomed)}개를 지웠습니다 — 명세에서 온 것만 지웠고 "
          f"링크·JS 로 찾은 화면은 그대로 둡니다", "ok")
    return redirect(_surface_url(tid))


@bp.post("/surface/clear")
def surface_clear():
    tid = request.form.get("target_id", type=int)
    db = get_db()
    db.execute("DELETE FROM points WHERE target_id = ?", [tid])
    db.commit()
    flash("수집된 지점을 비웠습니다(결과 탭의 결과는 남음)", "ok")
    return redirect(_surface_url(tid))


# ── 탐색(값을 넣고 결과 표를 보는 모듈, 옛 이름 도구 · 코드 이름 tool) ───────────────────────
#
# 전에는 도구만 요청 안에서 끝까지 돌았다(그 자리에서 결과를 그리려고). 모듈 탭에서
# 누르면 돌지도 않고 도구 탭으로 넘어갔고, 도구 탭에서는 끝날 때까지 화면이 멈췄다.
# 이제 도구도 다른 모듈처럼 뒤에서 돌고 '도는 중' 으로 간다(사용자 결정 11-07, 안 1).
# 그 대신 화면에 그릴 결과(표·내용)를 runs.result 에 남기고, 도구 탭은 그것을 다시 연다.

def _tool_modules(target):
    return {k: m for k, m in _modules_for(target).items() if m.stage == "tool"}


def _result_to_json(result):
    """ToolResult → 화면에 다시 그릴 만큼만. 찾은 것은 결과 탭에 따로 저장된다."""
    return json.dumps({
        "summary": result.summary,
        "columns": [str(c) for c in result.columns],
        "rows": [[str(v) for v in row] for row in result.rows],
        "drills": result.drills,
        "text": result.text,
        "note": result.note,
        "more": result.more,
        "findings": [{"severity": f.severity, "title": f.title} for f in result.findings],
    }, ensure_ascii=False)


def _tool_call(mod, t, params):
    """작업자 스레드에서 도구를 돌리고, 결과 표를 그 실행 기록에 남긴다."""
    def call(target_):
        result = mod.run(target_, params)
        if not isinstance(result, ToolResult):
            raise TypeError("도구 모듈의 run() 은 ToolResult 를 돌려줘야 합니다")
        db = get_db()
        new = sum(_save_finding(mod, t["id"], f) for f in result.findings)
        msg = result.summary + (f" · 결과 {len(result.findings)}건(새로 {new})" if result.findings else "")
        if result.points:
            kept, skipped = _save_points(mod, t["id"], result.points)
            msg += f" · 표면에 {len(result.points) - skipped}개(새로 {kept})"
            if skipped:
                msg += f", 범위 밖 {skipped}개 제외"
        db.execute("UPDATE runs SET result = ? WHERE id = ?", [_result_to_json(result), g.run_id])
        # 본문(퍼징 트리 등)은 파일로도 떨군다. 화면 복원은 위의 result 로 되지만, 트리는
        # 보고서에 붙이고 팀에 넘기는 산출물이다 — 받아 쓰는 사람이 sqlite 를 열게 할 수 없다
        if result.text:
            runfiles.save(current_app, g.run_id, t, mod, result.text, result.summary)
        return msg
    return call


def _tool_run_row(target, mod, run_id=None):
    """보여 줄 실행. 번호를 주면 그것, 없으면 이 대상·도구의 가장 최근 실행."""
    if not (target and mod):
        return None
    db = get_db()
    if run_id:
        return db.execute("SELECT * FROM runs WHERE id = ? AND target_id = ? AND module_id = ?",
                          [run_id, target["id"], mod.id]).fetchone()
    return db.execute("SELECT * FROM runs WHERE target_id = ? AND module_id = ? ORDER BY id DESC LIMIT 1",
                      [target["id"], mod.id]).fetchone()


def _tool_page(target, targets, mod, values, run=None):
    tools = _shown(_tool_modules(target))
    # 도는 중인 도구는 화면에도 적는다. 결과 자리가 비어 있으면 아무 일도 없던 것 같다.
    live = [j for j in jobs.listing(target["id"]) if j["live"] and j["module_id"] in tools] if target else []
    result = json.loads(run["result"]) if run is not None and run["result"] else None
    # 본문이 있으면 파일로도 남아 있다 — 어디에 적혔는지 화면에 알려 줘야 가져다 쓴다
    text_file = runfiles.find(current_app, target, mod.id, run["id"]) if (result and result.get("text")) else None
    return render_template("tools.html", tools=tools, mod=mod, values=values, result=result, run=run,
                           target=target, targets=targets, live_tools=live,
                           text_file=str(text_file) if text_file else "")


@bp.get("/tools")
def tools():
    target, targets = _current_target()
    tools_ = _shown(_tool_modules(target))
    mod = tools_.get(request.args.get("tool") or "") or (next(iter(tools_.values())) if tools_ else None)
    values = {p["name"]: p.get("default", "") for p in mod.params} if mod else {}
    run = _tool_run_row(target, mod, request.args.get("run", type=int))
    if run is not None:
        # 그 실행에 넣었던 값으로 칸을 채운다 — '이어서 보기' 가 같은 값에서 출발한다
        try:
            saved = json.loads(run["params"] or "{}")
        except ValueError:
            saved = {}
        values.update({k: str(v) for k, v in saved.items() if k in values})
    return _tool_page(target, targets, mod, values, run)


@bp.post("/tools/run")
def tool_run():
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [request.form.get("target_id", type=int)]).fetchone()
    if not t:
        flash("대상을 먼저 고르세요", "error")
        return redirect(url_for("dash.tools"))
    mod = _tool_modules(t).get(request.form.get("module_id", "")) or abort(404)
    back = url_for("dash.tools", target=t["id"], tool=mod.id)
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
    stop = _guard(mod, t, back)
    if stop:
        return stop
    try:
        params = _check_types(mod, values)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(back)

    run_id = _execute_bg(mod, t, params, _tool_call(mod, t, params))
    return redirect(url_for("dash.tools", target=t["id"], tool=mod.id, run=run_id) if run_id else back)


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

def _attack_columns(target):
    """ATT&CK 매트릭스 — 전술 15개 열(v20.1), 칸은 모듈이 다루는 기법."""
    hit = set()
    if target:
        hit = {r["technique"] for r in get_db().execute(
            "SELECT DISTINCT technique FROM findings WHERE target_id = ? AND status != 'false_positive'",
            [target["id"]])}
    columns = []
    for tid, en, ko in TACTICS:
        cells = {}
        for mod in _shown(_modules_for(target)).values():
            for a in mod.attack:
                if a["tactic"] == tid:
                    cell = cells.setdefault(a["technique"], {"technique": a["technique"], "name": a.get("name", ""),
                                                             "modules": [], "hit": a["technique"] in hit,
                                                             "url": technique_url(a["technique"])})
                    cell["modules"].append(mod.name)
        columns.append({"id": tid, "en": en, "ko": ko, "cells": list(cells.values())})
    return columns


@bp.get("/attack")
def attack():
    """옛 ATT&CK 탭 주소. 수사보드 페이지의 매트릭스 탭으로 보낸다."""
    return redirect(url_for("dash.scenario", target=request.args.get("target", type=int)) + "#matrix")


@bp.get("/scenario")
def scenario():
    """수사보드와 ATT&CK 매트릭스를 한 페이지의 두 탭으로 보여 준다.

    수사보드 탭은 왼쪽이 후보(관찰한 버전·CVE·결과·제안 모듈), 오른쪽이 팀이 고른 캠페인 보드다.
    """
    target, targets = _current_target()
    rows, head, cands, camps, current = [], {}, None, [], None
    if target:
        db = get_db()
        found = db.execute(
            "SELECT * FROM findings WHERE target_id = ? AND status IN ('open', 'confirmed') "
            "ORDER BY " + SEVERITY_ORDER_SQL, [target["id"]]).fetchall()
        rows = board.build(found, list(_shown(_modules_for(target)).values()), _technique_tactic(),
                           lambda m: module_needs(m, target))
        head = board.summary(rows)
        cands = cve.candidates(db, target, found, current_app.config["PROJECTS_PKG"])
        camps = campaign.for_target(db, target["id"])
        want = request.args.get("campaign", type=int)
        pick = next((c for c in camps if c["id"] == want), camps[-1] if camps else None)
        current = campaign.state(db, pick["id"]) if pick else None
    return render_template("scenario.html", rows=rows, head=head, columns=_attack_columns(target),
                           cands=cands, campaigns=camps, current=current, tactics=TACTICS,
                           target=target, targets=targets, all_modules=_modules())


# ── 캠페인 보드 ─────────────────────────────────────────────
# 화면의 끌어다 놓기·잇기는 JS 가 아래 주소로 보내고, 돌아온 캠페인 상태(JSON)로 다시 그린다.

def _campaign_or_404(cid):
    c = get_db().execute("SELECT * FROM campaigns WHERE id = ?", [cid]).fetchone()
    return c or abort(404)


def _board_url(tid, cid=None):
    return url_for("dash.scenario", target=tid, campaign=cid) + "#board"


@bp.post("/campaigns")
def campaign_create():
    tid = request.form.get("target_id", type=int)
    get_db().execute("SELECT id FROM targets WHERE id = ?", [tid]).fetchone() or abort(404)
    name = request.form.get("name", "").strip()
    if not name:
        flash("캠페인 이름을 적으세요", "error")
        return redirect(_board_url(tid))
    cid = campaign.create(get_db(), tid, name, request.form.get("goal", ""))
    return redirect(_board_url(tid, cid))


@bp.post("/campaigns/<int:cid>/delete")
def campaign_delete(cid):
    c = _campaign_or_404(cid)
    campaign.delete(get_db(), cid)
    flash(f"캠페인 '{c['name']}' 을 지웠습니다", "ok")
    return redirect(_board_url(c["target_id"]))


def _campaign_json(cid, fn):
    """캠페인을 바꾸는 요청 공통: 바꾸고 새 상태를 돌려준다. 틀린 값은 400 과 이유."""
    _campaign_or_404(cid)
    db = get_db()
    try:
        fn(db)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except LookupError:
        abort(404)
    return jsonify(campaign.state(db, cid))


@bp.post("/campaigns/<int:cid>/nodes")
def campaign_node_add(cid):
    f = request.form
    return _campaign_json(cid, lambda db: campaign.add_node(
        db, cid, f.get("kind", ""), f.get("tactic", ""), f.get("title", ""), ref=f.get("ref", ""),
        sub=f.get("sub", ""), status=f.get("status", ""), note=f.get("note", "")))


@bp.post("/campaigns/<int:cid>/nodes/<int:nid>")
def campaign_node_update(cid, nid):
    f = request.form
    return _campaign_json(cid, lambda db: campaign.update_node(
        db, cid, nid, tactic=f.get("tactic"), status=f.get("status"), note=f.get("note"), title=f.get("title")))


@bp.post("/campaigns/<int:cid>/nodes/<int:nid>/delete")
def campaign_node_delete(cid, nid):
    return _campaign_json(cid, lambda db: campaign.delete_node(db, cid, nid))


@bp.post("/campaigns/<int:cid>/edges")
def campaign_edge_add(cid):
    f = request.form
    return _campaign_json(cid, lambda db: campaign.add_edge(
        db, cid, f.get("src", type=int), f.get("dst", type=int), f.get("label", "")))


@bp.post("/campaigns/<int:cid>/edges/<int:eid>")
def campaign_edge_update(cid, eid):
    return _campaign_json(cid, lambda db: campaign.update_edge(db, cid, eid, request.form.get("label", "")))


@bp.post("/campaigns/<int:cid>/edges/<int:eid>/delete")
def campaign_edge_delete(cid, eid):
    return _campaign_json(cid, lambda db: campaign.delete_edge(db, cid, eid))


@bp.post("/cve/nvd")
def cve_nvd():
    """관찰한 버전으로 NVD 를 묻는다. 대상이 아니라 services.nvd.nist.gov 로 나가는 요청이라 버튼으로만."""
    tid = request.form.get("target_id", type=int)
    db = get_db()
    db.execute("SELECT id FROM targets WHERE id = ?", [tid]).fetchone() or abort(404)
    found = db.execute("SELECT * FROM findings WHERE target_id = ? AND status != 'false_positive'", [tid]).fetchall()
    observed = cve.observe(found)
    if not observed:
        flash("버전이 보이는 결과가 없습니다. '서버 정보 노출' 모듈을 먼저 돌리세요", "error")
        return redirect(_board_url(tid, request.form.get("campaign", type=int)))
    asked, failed = cve.refresh(db, observed, fetch=current_app.config.get("NVD_FETCH") or cve.fetch_nvd,
                                pause=current_app.config.get("NVD_PAUSE_S", cve.NVD_PAUSE_S))
    if failed:
        flash(f"NVD 조회 {asked}건 중 {len(failed)}건 실패 — {failed[0][1]}", "error")
    else:
        flash(f"NVD 에서 제품 {len(observed)}개({asked}건)를 찾았습니다", "ok")
    return redirect(_board_url(tid, request.form.get("campaign", type=int)))


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
        "tool": "딸깍이 (DAST 대시보드)", "version": current_app.jinja_env.globals["VERSION"], "generated_at": now_iso(),
        # practice 와 원시 id 를 같이 준다 — 받는 쪽이 한국어 이름을 부분일치로
        # 뒤지지 않게. 가짜 서버의 결과가 점검 결과로 섞여 들어가면 안 된다.
        "practice": _is_practice(t),
        "target": {"name": t["name"], "url": t["url"], "project": _project_of(t).name,
                   "role": _role_label(t), "project_id": t["project"], "role_id": t["role"],
                   "practice": _is_practice(t)},
        "findings": [{
            "title": r["title"], "severity": r["severity"], "status": r["status"], "location": r["location"],
            "module": mods[r["module_id"]].name if r["module_id"] in mods else r["module_id"],
            "attack": {"technique": r["technique"], "url": technique_url(r["technique"]) if r["technique"] else ""},
            "evidence": r["evidence"], "recommendation": r["recommendation"],
            "cvss": _rate(r["cvss_vector"] if "cvss_vector" in r.keys() else "", mods.get(r["module_id"])),
            "first_seen": r["created_at"], "last_seen": r["last_seen"], "exchange": exchanges.get(r["id"]),
        } for r in rows],
    }
    return Response(json.dumps(data, ensure_ascii=False, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=report_{tid}.json"})


# 팀 결과보고서 양식의 자산 ID·구역. 역할 하나가 자산 하나다
# (`01_제출물/결과보고서_양식/1_결과보고서_양식.md` 의 공통 ID 체계).
ASSETS = {"user_web": ("A-01", "외부(DMZ)"), "admin_web": ("A-02", "관리·내부"),
          "admin_api": ("A-03", "관리·내부")}


@bp.get("/report/<int:tid>.docx")
def report_docx(tid):
    """내려받기 단추가 주는 것 — 팀 결과보고서 양식에 맞춘 Word(11-21 사용자 지시)."""
    from io import BytesIO

    from . import __version__
    from . import report_docx as maker

    t, rows, exchanges = _report_rows(tid)
    mods = _modules()
    asset, zone = ASSETS.get(t["role"], ("[ ]", "[ ]"))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top = {}
    for r in rows:
        key = r["module_id"]
        if key not in top or rank.get(r["severity"], 9) < rank.get(top[key], 9):
            top[key] = r["severity"]
    items = []
    for r in rows:
        mod = mods.get(r["module_id"])
        rated = _rate(r["cvss_vector"] if "cvss_vector" in r.keys() else "", mod)
        x = exchanges.get(r["id"]) or {}
        items.append({
            "module_id": r["module_id"], "module_name": mod.name if mod else r["module_id"],
            "module_desc": (mod.description if mod else "").replace("**", ""),
            # 항목 코드 — KISA 21항목이 있으면 그것, 없으면 자체 항목(X-xx). 비워 두지 않는다
            "kisa": (" · ".join(standards.item_label(c) for c in (mod.kisa if mod else []))
                     or (standards.item_label(mod.item) if mod and mod.item else "")),
            "owasp": " · ".join(f"{k} {standards.OWASP_NAME[k]}" for k in (mod.owasp if mod else [])),
            "title": r["title"], "location": r["location"], "severity": r["severity"],
            "severity_label": SEVERITY_LABEL[r["severity"]],
            "top_severity": SEVERITY_LABEL[top.get(r["module_id"], r["severity"])],
            # 사람이 화면에서 벡터를 확정했으면 그 점수, 아직이면 모듈 제안값에 '(제안)' 을 붙인다.
            # 비워 두면 보고서에서 '점수 없음' 으로 읽힌다(11-22 사용자 지적)
            "cvss_score": ("" if not rated else
                           (f'{rated["score"]}' if rated["saved"] else f'{rated["score"]} (제안)')),
            "cvss_vector": (rated or {}).get("vector", ""),
            "status_label": STATUSES.get(r["status"], r["status"]),
            "recommendation": r["recommendation"] or "",
            "evidence": r["evidence"] or "", "request": x.get("request", ""), "response": x.get("response", ""),
            "method": maker._method_of(x.get("request", "")),
        })
    doc_meta = {
        "practice": _is_practice(t), "project": _project_of(t).name, "written": fmt_kst(now_iso()),
        "target_name": t["name"], "url": t["url"], "asset_id": asset, "zone": zone,
        "tool": f"딸깍이 {__version__}",
    }
    buf = BytesIO()
    maker.build(doc_meta, items, buf)
    buf.seek(0)
    name = f"점검결과_{_slug_name(t['name'])}_{now_iso()[:10]}.docx"
    return Response(buf.read(), mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})


def _slug_name(s):
    return re.sub(r"[^0-9A-Za-z가-힣._-]+", "_", str(s or "")).strip("_") or "보고서"


@bp.get("/report/<int:tid>.md")
def report(tid):
    t, rows, exchanges = _report_rows(tid)
    mods = _modules()
    # 연습용은 제목부터 다르게 쓴다. 같은 양식으로 내보내면 복사해 붙였을 때
    # 실제 점검 결과와 구별이 안 된다 — 가짜 서버에서 나온 것이다.
    practice = _is_practice(t)
    lines = [f"# 연습 기록 — {t['name']}" if practice else f"# 점검 결과 — {t['name']}", ""]
    if practice:
        lines += ["> **점검 결과가 아닙니다.** 우리가 띄운 연습용 가짜 서버"
                  "(`demo_target.py`)에서 나온 기록입니다. 보고서에 넣지 마세요.", ""]
    lines += ["- 도구: 딸깍이 (DAST 대시보드)",
             f"- 프로젝트: {_project_of(t).name}" + (" (연습용 — 점검 범위 아님)" if practice else ""),
             f"- 대상: {t['url']}" + (f" ({_role_label(t)})" if _role_label(t) else ""),
             f"- 작성: {fmt_kst(now_iso())} (KST)", f"- 발견: {len(rows)}건", "",
             "| # | 심각도 | 항목 | 위치 | ATT&CK | 상태 |", "|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        # 주소는 **코드로** 적는다. 그냥 두면 보는 도구가 링크로 만들고, 누르면 토큰이 없어
        # `{"code":"UNAUTHORIZED"}` 나 JSON 덩어리가 뜬다(11-21 사용자 지적). 증거는 아래 요청·응답이다
        lines.append(f"| {i} | {SEVERITY_LABEL[r['severity']]} | {r['title']} | `{r['location']}` | "
                     f"{r['technique']} | {STATUSES.get(r['status'], r['status'])} |")
    lines += ["", "> 위치는 **어디서 났는지** 적어 둔 주소입니다 — 눌러 보는 링크가 아닙니다. "
                  "브라우저로 그대로 열면 로그인이 필요하다고 하거나(`UNAUTHORIZED`) 데이터(JSON)만 나옵니다. "
                  "무엇을 보내 무엇을 받았는지는 각 항목의 **요청·응답**에 그대로 있습니다."]
    for i, r in enumerate(rows, 1):
        mod = mods.get(r["module_id"])
        rated = _rate(r["cvss_vector"] if "cvss_vector" in r.keys() else "", mod)
        saved = rated and rated["saved"]
        # 팀 노션 '웹 서비스 취약점 목록' 의 본문 양식 그대로 — 1.개요 / 2.상세 / 3.시나리오 / 4.조치
        lines += ["", f"## {i}. {r['title']}", "", "### 1. 취약점 개요", "",
                  "| 항목 | 내용 |", "|---|---|",
                  f"| 취약점명 | {r['title']} |",
                  f"| 점검대상 | {t['name']} ({t['url']}) |",
                  f"| 발견 경로 | `{r['location']}` |",
                  f"| 취약점 설명 | {r['title']} — {mod.description if mod else ''} |",
                  f"| 영향도(CVSS 3.1) | {rated['impact_text'] if saved else (rated['impact_text'] + ' — **미확정(모듈 제안값)**' if rated else '**미평가**')} |",
                  f"| CVSS Vector | {('`' + rated['vector'] + '`') if rated else '—'} |",
                  f"| 발견 모듈 | {mod.name if mod else r['module_id']} |",
                  f"| ATT&CK | [{r['technique']}]({technique_url(r['technique'])}) |",
                  f"| 상태 | {STATUSES.get(r['status'], r['status'])} |",
                  "", "### 2. 취약점 상세설명", "", "**근거**", "", "```", r["evidence"], "```"]
        if r["id"] in exchanges:
            x = exchanges[r["id"]]
            lines += ["", "**요청**", "", "```http", x["request"], "```", "", "**응답(앞부분)**", "", "```http",
                      x["response"], "```"]
        lines += ["", "### 3. 악용 시나리오", "",
                  "_여기는 사람이 씁니다 — 이 결과로 무엇을 할 수 있는지._",
                  "", "### 4. 조치방안", "", r["recommendation"]]
    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=report_{tid}.md"})


# ── MCP — AI 도구가 딸깍이를 도구로 쓴다(11-21 사용자 결정) ──────────────────────
# 말을 주고받는 자리는 dashboard/mcp.py 에, **실제로 하는 일** 은 여기에 둔다. 화면이 쓰는
# 바로 그 함수들(_execute_bg·_probe_points·_save_finding·stats)을 그대로 불러서, 화면으로 한
# 것과 MCP 로 한 것이 다른 길로 가지 않게 한다.

def _mcp_target(tid):
    t = get_db().execute("SELECT * FROM targets WHERE id = ?", [tid]).fetchone()
    if not t:
        raise ValueError(f"그런 대상이 없습니다: {tid}. `targets` 로 목록을 보세요")
    return t


def _mcp_lines(rows, head=""):
    return (head + "\n" if head else "") + ("\n".join(rows) if rows else "(없음)")


def _mcp_targets(_a):
    db = get_db()
    out = []
    for t in db.execute("SELECT * FROM targets ORDER BY id"):
        n = db.execute("SELECT COUNT(*) FROM points WHERE target_id = ?", [t["id"]]).fetchone()[0]
        f = db.execute("SELECT COUNT(*) FROM findings WHERE target_id = ?", [t["id"]]).fetchone()[0]
        out.append(f'{t["id"]}\t{t["name"]}\t{t["url"]}\t역할 {t["role"] or "-"}\t지점 {n}\t결과 {f}')
    return _mcp_lines(out, "id\t이름\t주소\t역할\t지점\t결과")


def _mcp_points(a):
    t = _mcp_target(a.get("target_id"))
    sql = "SELECT * FROM points WHERE target_id = ?"
    args = [t["id"]]
    if a.get("params_only"):
        sql += " AND param != ''"
    if a.get("contains"):
        sql += " AND url LIKE ?"
        args.append("%" + str(a["contains"]) + "%")
    sql += " ORDER BY url LIMIT ?"
    args.append(int(a.get("limit") or 100))
    rows = get_db().execute(sql, args).fetchall()
    out = [f'{r["id"]}\t{r["method"]}\t{r["url"]}\t{r["param"] or "-"}\t{r["place"]}\t{r["source"] or "-"}'
           for r in rows]
    return _mcp_lines(out, "id\t메서드\t주소\t파라미터\t자리\t출처")


def _mcp_modules(a):
    t = _mcp_target(a.get("target_id"))
    out = []
    for m in _shown(_modules_for(t)).values():
        names = ",".join(p["name"] for p in m.params) or "-"
        out.append(f'{m.id}\t{m.name}\t{m.stage}\t{getattr(m, "vuln", "") or "-"}\t{m.severity}\t설정 {names}')
    return _mcp_lines(sorted(out), "id\t이름\t단계\t종류\t심각도\t설정 칸\n"
                                   "(단계 probe 는 points 로 지점을 골라야 돕니다)")


def _mcp_findings(a):
    sql = "SELECT f.*, t.name tname FROM findings f JOIN targets t ON t.id = f.target_id WHERE 1=1"
    args = []
    for key, col in (("target_id", "f.target_id"), ("status", "f.status"), ("severity", "f.severity")):
        if a.get(key):
            sql += " AND " + col + " = ?"
            args.append(a[key])
    if a.get("contains"):
        sql += " AND (f.title LIKE ? OR f.location LIKE ?)"
        args += ["%" + str(a["contains"]) + "%"] * 2
    sql += " ORDER BY f.id DESC LIMIT ?"
    args.append(int(a.get("limit") or 50))
    rows = get_db().execute(sql, args).fetchall()
    out = [f'{r["id"]}\t{r["tname"]}\t{r["severity"]}\t{STATUSES.get(r["status"], r["status"])}\t'
           f'{r["title"]}\t{r["location"]}' for r in rows]
    return _mcp_lines(out, "id\t대상\t심각도\t상태\t제목\t자리")


def _mcp_finding(a):
    r = get_db().execute("SELECT f.*, t.name tname, t.url turl FROM findings f JOIN targets t ON t.id = f.target_id "
                         "WHERE f.id = ?", [a.get("id")]).fetchone()
    if not r:
        raise ValueError(f'그런 결과가 없습니다: {a.get("id")}')
    return (f'#{r["id"]} {r["title"]}\n'
            f'대상: {r["tname"]} {r["turl"]}\n자리: {r["location"]}\n'
            f'심각도: {r["severity"]} · 상태: {STATUSES.get(r["status"], r["status"])} · 모듈: {r["module_id"]}\n'
            f'\n[근거]\n{r["evidence"]}\n\n[권고]\n{r["recommendation"] or "(없음)"}')


def _mcp_coverage(_a):
    db = get_db()
    real = [t for t in db.execute("SELECT * FROM targets ORDER BY id") if not _is_practice(t)]
    bd = stats.breakdown(db, real, _modules())
    label = {"found": "발견", "clear": "점검·없음", "ready": "모듈 있음·미실행", "none": "모듈 없음"}
    out = [f'{r["key"]}\t{label[r["state"]]}\t{r["total"]}건\t{r["name"]}' for r in bd["owasp"]]
    out.append("")
    out += [f'{r["code"]}\t{label[r["state"]]}\t{r["found"]}건\t{r["name"]}' for r in bd["kisa"]]
    return _mcp_lines(out, "항목\t상태\t건수\t이름")


def _mcp_run_status(a):
    rid = a.get("run_id")
    rows = jobs.listing()
    if rid:
        rows = [j for j in rows if j["run_id"] == rid]
        if not rows:
            r = get_db().execute("SELECT * FROM runs WHERE id = ?", [rid]).fetchone()
            if not r:
                raise ValueError(f"그런 실행이 없습니다: {rid}")
            return (f'{rid}\t{r["status"]}\t{r["module_id"]}\t보낸 요청 {r["sent"]}\t'
                    f'{r["message"] or r["error"] or ""}')
    out = [f'{j["run_id"]}\t{j["status"]}\t{j["module_id"]}\t{j["target"]}\t보낸 요청 {j["sent"]}\t'
           f'{int(j["seconds"])}초\t{j["message"] or j["error"] or ""}' for j in rows]
    return _mcp_lines(out, "run_id\t상태\t모듈\t대상\t요청\t시간\t메시지")


def _mcp_run_module(a):
    t = _mcp_target(a.get("target_id"))
    mod = _modules_for(t).get(a.get("module_id", ""))
    if not mod:
        raise ValueError(f'이 대상에서 쓸 수 없는 모듈입니다: {a.get("module_id")}. `modules` 로 목록을 보세요')
    blocked = _need_block(mod, t)
    if blocked:
        raise ValueError(blocked)
    given = a.get("params") or {}
    params = _check_types(mod, {p["name"]: str(given.get(p["name"], p.get("default", ""))) for p in mod.params})
    ids = [int(x) for x in (a.get("points") or [])]
    if mod.stage == "probe":
        if not ids:
            raise ValueError(f"{mod.name} 은 지점 점검 모듈입니다. `points` 로 지점 id 를 골라 넣으세요")
        pts = _probe_points(t, mod, ids)
        if not pts:
            raise ValueError("고른 지점을 찾지 못했습니다(그 대상의 지점 id 가 맞는지 보세요)")
        run_id = _execute_bg(mod, t, {**params, "points": len(pts)}, _probe_call(mod, t, pts, params))
        made = f"지점 {len(pts)}개"
    elif mod.stage == "collect":
        def call(target):
            points = mod.run(target, params) or []
            new, skipped = _save_points(mod, t["id"], points)
            # 범위 밖이라 빠진 수까지 적는다 — 화면과 같은 말이 남아야 둘을 견줄 수 있다
            return (f"지점 {len(points) - skipped}개 수집(새로 {new})"
                    + (f", 범위 밖 {skipped}개 제외" if skipped else ""))
        run_id = _execute_bg(mod, t, params, call)
        made = "수집"
    elif mod.stage == "tool":
        run_id = _execute_bg(mod, t, params, _tool_call(mod, t, params))
        made = "도구"
    else:
        def call(target):
            results = mod.run(target, params) or []
            new = sum(_save_finding(mod, t["id"], f) for f in results)
            return f"{len(results)}건 발견(새로 {new})"
        run_id = _execute_bg(mod, t, params, call)
        made = "점검"
    if not run_id:
        raise ValueError(f"지금 {jobs.MAX_LIVE}개가 돌고 있습니다. 하나 끝나면 다시 부르세요")
    return (f'{mod.name} 을 {t["name"]} 에 돌리기 시작했습니다({made}).\n'
            f'run_id {run_id} — 진행은 `run_status` 로 보세요. 뒤에서 돌므로 이 호출은 바로 돌아옵니다.')


def _mcp_set_status(a):
    status = a.get("status", "")
    if status not in STATUSES:
        raise ValueError("상태는 " + ", ".join(STATUSES) + " 중 하나여야 합니다")
    db = get_db()
    r = db.execute("SELECT * FROM findings WHERE id = ?", [a.get("id")]).fetchone()
    if not r:
        raise ValueError(f'그런 결과가 없습니다: {a.get("id")}')
    ev = r["evidence"]
    if a.get("note"):
        # 판정만 바뀌고 까닭이 없으면 다음 사람이 처음부터 다시 봐야 한다 — 근거 끝에 붙여 둔다
        ev = ev + f'\n\n[{STATUSES[status]} — MCP] {a["note"]}'
    db.execute("UPDATE findings SET status = ?, evidence = ? WHERE id = ?", [status, ev, r["id"]])
    db.commit()
    return f'#{r["id"]} {r["title"]} → {STATUSES[status]}'


# ── 점검 결과 → CVE 후보 → 시나리오 한 벌(11-21 사용자 제안) ─────────────────────
# "딸깍이 점검으로 나온 정보로 CVE 위험 가능성 있는 목록을 뽑고, 그걸로 펜테스트 캠페인
# 하나를 짜 주면 보고서에 올리기 편하다." 재료는 이미 다 있다 — 관찰한 버전(cve.observe),
# 팀 CVE 목록, 전술이 붙은 모듈·결과. 손으로 옮겨 적던 그 일을 한 번에 한다.
#
# **짜 주는 것은 초안이다.** 노드의 상태는 결과의 처리 상태를 그대로 따른다(확인됨 → 확인,
# 미확인 → 추정). 선은 전술 순서대로 한 줄로만 잇는다 — 어느 단계에서 무엇을 얻어 다음에
# 넘겼는지는 팀이 보드에서 고쳐 적는다. 대시보드는 그 데이터를 갖고 있지 않다(board.py 머리).

def _findings_of(tid):
    return get_db().execute("SELECT * FROM findings WHERE target_id = ? ORDER BY id", [tid]).fetchall()


def _mcp_cve_candidates(a):
    t = _mcp_target(a.get("target_id"))
    db = get_db()
    rows = _findings_of(t["id"])
    if a.get("ask_nvd"):
        # 점검 대상이 아니라 NVD(services.nvd.nist.gov)로 나간다. 보내는 것은 제품·버전뿐이다
        cve.refresh(db, cve.observe(rows))
    got = cve.candidates(db, t, rows)
    out = []
    for o in got["observed"]:
        head = f'{o["product"]} {o["version"]}' + (f' ({o["distro"]})' if o["distro"] else "")
        out.append(f'\n[관찰] {head}\t근거 #{o["finding_id"]} {o["title"]} — {o["location"]}')
        if not o.get("asked"):
            out.append("   NVD 에 아직 안 물어봤습니다 — ask_nvd 를 켜면 물어봅니다")
        for c in o["cves"][:8]:
            mark = "팀" if c["team"] else ("KEV" if c["kev"] else "  ")
            out.append(f'   {mark}\t{c["id"]}\t{c["score"] or "-"}\t{c["status"]}\t{c["summary"][:90]}')
    if got["team"]:
        out.append("\n[팀 목록] 문서에 적힌 것 — 밖에서 버전이 안 보여도 여기 있습니다")
        for c in got["team"]:
            seen = "지금도 보임" if c.get("seen_now") else ""
            out.append(f'   {c["id"]}\t{c["status"]}\t{c["product"]} {c["version"]}\t{seen}')
    return _mcp_lines(out, f'{t["name"]} — 관찰한 제품 {len(got["observed"])}개') if out else \
        "관찰된 제품·버전이 없습니다. 기술 지문(tech_fingerprint)·서버 정보 노출 모듈을 먼저 돌리세요"


# 결과를 어느 전술 열에 놓을지 — 모듈이 적어 둔 첫 전술을 쓴다. 없으면 '발견'(TA0043)
FALLBACK_TACTIC = "TA0043"


def _tactic_of(mid):
    mod = _modules().get(mid)
    got = (getattr(mod, "attack", None) or [{}])[0].get("tactic", "") if mod else ""
    return got if got in TACTIC_NAME else FALLBACK_TACTIC


def _mcp_make_campaign(a):
    t = _mcp_target(a.get("target_id"))
    db = get_db()
    want = set(a.get("statuses") or ["confirmed"])
    rows = [r for r in _findings_of(t["id"]) if r["status"] in want and r["severity"] != "info"]
    if not rows:
        raise ValueError(f'{t["name"]} 에 {"·".join(want)} 상태인 결과가 없습니다. '
                         "statuses 에 open 을 넣거나 `findings` 로 먼저 보세요")
    name = (a.get("name") or f'{t["name"]} 침투 시나리오').strip()
    cid = campaign.create(db, t["id"], name, a.get("goal") or "")

    # ① 관찰한 버전과 팀 CVE 를 앞단(정찰·초기 침투)에 놓는다 — 밖에서 보이는 것이 먼저다
    got = cve.candidates(db, t, _findings_of(t["id"]))
    first = []
    for o in got["observed"][:6]:
        nid = campaign.add_node(db, cid, "observed", "TA0043", f'{o["product"]} {o["version"]}',
                                ref=f'{o["product"]} {o["version"]}', sub=o["location"], status="확인",
                                note=f'근거: 결과 #{o["finding_id"]}')
        first.append(nid)
        for c in (o.get("cves") or [])[:2]:
            campaign.add_node(db, cid, "cve", "TA0001", c["id"], ref=c["id"],
                              sub=f'{o["product"]} {o["version"]} · 점수 {c["score"] or "-"}',
                              status=c["status"], note=c["summary"][:300])
    for c in got["team"][:6]:
        campaign.add_node(db, cid, "cve", "TA0001", c["id"], ref=c["id"],
                          sub=f'{c["product"]} {c["version"]}', status=c["status"], note=c.get("note", "")[:300])

    # ② 결과를 모듈이 적어 둔 전술 열에 놓는다. 상태는 결과의 처리 상태를 그대로 따른다
    by_tactic = {}
    for r in rows:
        tac = _tactic_of(r["module_id"])
        nid = campaign.add_node(db, cid, "finding", tac, r["title"], ref=str(r["id"]), sub=r["location"],
                                status="확인" if r["status"] == "confirmed" else "추정",
                                note=f'결과 #{r["id"]} · {r["severity"]}')
        by_tactic.setdefault(tac, []).append((nid, r))

    # ③ 전술 순서대로 한 줄로 잇는다. 무엇을 얻어 넘겼는지는 팀이 보드에서 적는다
    order = [tac for tac in TACTIC_ORDER if tac in by_tactic]
    chain = [by_tactic[tac][0][0] for tac in order]
    if first and chain:
        chain = [first[0]] + chain
    for src, dst in zip(chain, chain[1:]):
        campaign.add_edge(db, cid, src, dst, "")

    # ④ 보고서에 그대로 옮길 수 있는 줄거리
    lines = [f'캠페인 #{cid} 「{name}」 을 {t["name"]} 에 만들었습니다.',
             f'보드: /scenario?target={t["id"]}&campaign={cid}', ""]
    if got["observed"] or got["team"]:
        lines.append(f'정찰·초기 침투 — 관찰한 제품 {len(got["observed"])}개 · CVE 후보 '
                     f'{sum(len(o.get("cves") or []) for o in got["observed"]) + len(got["team"])}개')
    for i, tac in enumerate(order, 1):
        got_rows = by_tactic[tac]
        lines.append(f'{i}. {TACTIC_NAME[tac]} — {len(got_rows)}건')
        for _nid, r in got_rows[:4]:
            lines.append(f'   · [{r["severity"]}] {r["title"]} — {r["location"]}')
        if len(got_rows) > 4:
            lines.append(f'   · 그 밖 {len(got_rows) - 4}건')
    lines += ["", "선은 전술 순서대로 한 줄만 그었습니다. **어느 단계에서 무엇을 얻어 다음에 넘겼는지**"
                  "(토큰·비밀값·셸)는 보드에서 선을 눌러 적으세요 — 그건 사람이 아는 것입니다.",
              "CVE 후보는 버전 범위가 맞는다는 뜻일 뿐 '추정' 입니다. 확인한 것만 상태를 올리세요."]
    return "\n".join(lines)


MCP_TOOLS = {
    "targets": _mcp_targets, "points": _mcp_points, "modules": _mcp_modules,
    "findings": _mcp_findings, "finding": _mcp_finding, "coverage": _mcp_coverage,
    "run_status": _mcp_run_status, "run_module": _mcp_run_module, "set_status": _mcp_set_status,
    "cve_candidates": _mcp_cve_candidates, "make_campaign": _mcp_make_campaign,
}


def _mcp_error(code, message, status):
    body = {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}
    return Response(json.dumps(body, ensure_ascii=False), status=status, mimetype="application/json")


@bp.post("/mcp")
def mcp_endpoint():
    """JSON-RPC 한 자리. 토큰이 없으면 아무것도 안 한다."""
    if not mcp_mod.authorized():
        return _mcp_error(-32001, "토큰이 필요합니다 — 연결 탭에 적힌 줄을 그대로 쓰세요", 401)
    try:
        payload = json.loads(request.get_data(as_text=True) or "{}")
    except ValueError:
        return _mcp_error(-32700, "JSON 이 아닙니다", 400)
    out = mcp_mod.handle(payload, lambda name, args: MCP_TOOLS[name](args))
    if out is None:                       # 알림 — 돌려줄 것이 없다
        return Response("", status=202)
    return Response(json.dumps(out, ensure_ascii=False), mimetype="application/json")


@bp.get("/connect")
def connect():
    """연결 탭 — 붙이는 법, 켠 도구, 누가 무엇을 불렀는지."""
    target, targets = _current_target()
    return render_template("connect.html", target=target, targets=targets,
                           command=mcp_mod.connect_command(request.host_url),
                           tools=mcp_mod.TOOLS, write_on=mcp_mod.write_on(), calls=mcp_mod.recent(),
                           status=mcp_mod.status(), fresh=mcp_mod.FRESH_MIN)


@bp.get("/connect/state")
def connect_state():
    """붙었는지만 묻는 자리. 화면이 몇 초마다 물어보고 불을 켠다 —
    터미널에 줄을 넣은 사람이 **새로 고치지 않아도** 붙은 것이 보이게."""
    return mcp_mod.status()


@bp.post("/connect/write")
def connect_write():
    """쓰기 도구 스위치. 한 번 켜면 계속 켜져 있다 — 부를 때마다 사람을 부르지는 않는다."""
    mcp_mod.set_setting("mcp_write", "on" if request.form.get("on") == "1" else "off")
    flash("쓰기 도구를 켰습니다 — AI 가 모듈을 돌리고 결과 상태를 바꿀 수 있습니다" if mcp_mod.write_on()
          else "쓰기 도구를 껐습니다 — 읽기만 됩니다", "ok")
    return redirect(url_for("dash.connect", target=request.form.get("target_id", type=int)))


@bp.post("/connect/new-token")
def connect_new_token():
    """토큰을 새로 뽑는다 — 어딘가에 흘렸을 때. 붙여 둔 도구는 다시 붙여야 한다."""
    mcp_mod.set_setting("mcp_token", "")
    mcp_mod.token()
    flash("토큰을 새로 만들었습니다. 붙여 둔 도구는 새 줄로 다시 붙이세요", "ok")
    return redirect(url_for("dash.connect", target=request.form.get("target_id", type=int)))
