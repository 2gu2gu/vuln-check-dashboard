import json

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, url_for)

from . import scope
from .attack import TACTIC_NAME, TACTIC_ORDER, TACTICS, technique_url
from .core import SEVERITIES, SEVERITY_LABEL, Finding, Target, fmt_kst, now_iso
from .db import STATUSES, get_db
from .registry import GENERAL, modules_for

bp = Blueprint("dash", __name__)

SEVERITY_ORDER_SQL = "CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " END"


def _modules():
    return current_app.config["MODULES"]


def _projects():
    return current_app.config["PROJECTS"]


def _project_of(target):
    return _projects().get(target["project"]) or _projects()[GENERAL]


def _modules_for(target):
    """대상이 있으면 범용 + 그 프로젝트 전용, 없으면 전부."""
    return modules_for(_modules(), target["project"]) if target else _modules()


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
            scope.ensure_in_scope(url, _projects()[pid].scope)
            if not name:
                raise ValueError("이름을 넣어 주세요")
            db.execute("INSERT INTO targets (project, name, url, note, created_at) VALUES (?, ?, ?, ?, ?)",
                       [pid, name, url, request.form.get("note", "").strip(), now_iso()])
            db.commit()
            flash(f"대상을 등록했습니다: {name}", "ok")
        except Exception as e:  # noqa: BLE001
            flash(str(e), "error")
        return redirect(url_for("dash.targets"))
    target, targets = _current_target()
    return render_template("targets.html", target=target, targets=targets)


@bp.post("/targets/<int:tid>/delete")
def target_delete(tid):
    db = get_db()
    db.execute("DELETE FROM targets WHERE id = ?", [tid])
    db.commit()
    flash("대상을 지웠습니다(결과 포함)", "ok")
    return redirect(url_for("dash.targets"))


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
        "(SELECT COUNT(*) FROM findings f WHERE f.run_id = runs.id) AS n "
        "FROM runs JOIN targets ON targets.id = runs.target_id ORDER BY runs.id DESC LIMIT 15").fetchall()
    return render_template("modules.html", groups=groups, all_modules=_modules(), project=project,
                           hidden=len(_modules()) - len(available), errors=current_app.config["MODULE_ERRORS"],
                           target=target, targets=targets, runs=runs, tactic_name=TACTIC_NAME)


@bp.post("/modules/<mid>/run")
def module_run(mid):
    mod = _modules().get(mid) or abort(404)
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [request.form.get("target_id", type=int)]).fetchone()
    if not t:
        flash("대상을 먼저 고르세요", "error")
        return redirect(url_for("dash.modules"))
    if mod.project not in ("", t["project"]):
        flash(f"{mod.name} 은 {_projects()[mod.project].name} 전용 모듈입니다", "error")
        return redirect(url_for("dash.modules", target=t["id"]))
    if mod.kind == "active" and request.form.get("confirm") != "yes":
        flash("능동 모듈은 '자체 환경 확인'에 체크해야 실행됩니다", "error")
        return redirect(url_for("dash.modules", target=t["id"]))

    params = {p["name"]: request.form.get(p["name"], p.get("default", "")) for p in mod.params}
    cur = db.execute("INSERT INTO runs (target_id, module_id, params, status, started_at) VALUES (?, ?, ?, 'running', ?)",
                     [t["id"], mid, json.dumps(params, ensure_ascii=False), now_iso()])
    run_id = cur.lastrowid
    db.commit()
    g.scope_hosts = _project_of(t).scope  # 실행 중 core.fetch 는 이 범위로만 나간다
    try:
        scope.ensure_in_scope(t["url"])
        results = mod.run(Target(t["id"], t["name"], t["url"]), params) or []
        for f in results:
            if not isinstance(f, Finding):
                raise TypeError("run() 은 Finding 목록을 돌려줘야 합니다")
            db.execute(
                "INSERT INTO findings (run_id, target_id, module_id, title, severity, location, evidence, "
                "recommendation, technique, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [run_id, t["id"], mid, f.title, f.severity, f.location, f.evidence, f.recommendation,
                 f.technique or mod.attack[0]["technique"], now_iso()])
        db.execute("UPDATE runs SET status = 'done', finished_at = ? WHERE id = ?", [now_iso(), run_id])
        flash(f"{mod.name}: {len(results)}건 발견", "ok")
    except Exception as e:  # noqa: BLE001 — 실패도 실행 기록에 남긴다
        db.rollback()
        db.execute("UPDATE runs SET status = 'error', error = ?, finished_at = ? WHERE id = ?",
                   [str(e), now_iso(), run_id])
        flash(f"{mod.name} 실패: {e}", "error")
    finally:
        g.pop("scope_hosts", None)
    db.commit()
    return redirect(url_for("dash.results", target=t["id"]))


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


@bp.get("/report/<int:tid>.md")
def report(tid):
    db = get_db()
    t = db.execute("SELECT * FROM targets WHERE id = ?", [tid]).fetchone() or abort(404)
    rows = db.execute(f"SELECT * FROM findings WHERE target_id = ? AND status != 'false_positive' "
                      f"ORDER BY {SEVERITY_ORDER_SQL}, id", [tid]).fetchall()
    mods = _modules()
    lines = [f"# 점검 결과 — {t['name']}", "", f"- 프로젝트: {_project_of(t).name}", f"- 대상: {t['url']}",
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
    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=report_{tid}.md"})
