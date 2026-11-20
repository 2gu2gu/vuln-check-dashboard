"""결과 탭 위쪽 '점검 현황' 집계(11-20).

보고서 자동화 툴의 그림(위험도별 건수, 대상별 위험도 분포, 대상별 취약점 요약 표)과 같은 모양으로
보이게 한다 — 대시보드에서 본 것과 보고서에 실릴 것이 같은 그림이어야 한다.
'미조치' 는 조치됨·오탐을 뺀 것이다. 연습용 대상은 실서버가 아니라 빼고 센다.
"""
from .core import SEVERITIES

CLOSED = ("fixed", "false_positive")


def _ticks(top):
    """가로축 눈금 0·5·10… 처럼 깔끔한 간격으로. 막대가 축 끝을 넘지 않게 위로 올린다."""
    if top <= 0:
        return [0], 1
    step = next(s for s in (1, 2, 5, 10, 20, 25, 50, 100, 200, 500, 1000) if top / s <= 6)
    end = -(-top // step) * step
    return list(range(0, end + 1, step)), end


def overview(db, targets):
    """보이는 대상들의 미조치 심각도별 건수 + 합계 + 검토율."""
    ids = [t["id"] for t in targets]
    counts = {i: {s: 0 for s in SEVERITIES} for i in ids}
    reviewed = total_all = 0
    if ids:
        marks = ",".join("?" * len(ids))
        for r in db.execute(f"SELECT target_id, severity, status, COUNT(*) c FROM findings "
                            f"WHERE target_id IN ({marks}) GROUP BY target_id, severity, status", ids):
            total_all += r["c"]
            if r["status"] != "open":
                reviewed += r["c"]
            if r["status"] not in CLOSED and r["severity"] in SEVERITIES:
                counts[r["target_id"]][r["severity"]] += r["c"]
    rows = [{"target": t, "counts": counts[t["id"]], "total": sum(counts[t["id"]].values())} for t in targets]
    totals = {s: sum(r["counts"][s] for r in rows) for s in SEVERITIES}
    ticks, axis_end = _ticks(max((r["total"] for r in rows), default=0))
    for r in rows:
        r["segments"] = [{"severity": s, "n": r["counts"][s], "pct": r["counts"][s] * 100 / axis_end}
                         for s in SEVERITIES if r["counts"][s]]
    sev_top = max(totals.values(), default=0) or 1
    return {
        "rows": rows,
        "totals": totals,
        "total": sum(totals.values()),
        "sev_bars": [{"severity": s, "n": totals[s], "pct": totals[s] * 100 / sev_top} for s in SEVERITIES],
        "ticks": [{"n": n, "pct": n * 100 / axis_end} for n in ticks],
        "reviewed_pct": round(reviewed * 100 / total_all) if total_all else 0,
        "unreviewed": total_all - reviewed,
    }


# ── 진단 통계(11-20 추가): 맨 위 전체 숫자 · 유형별 · 주요정보통신기반시설 항목별 · 상태별 ──
#
# 결과 하나는 그 결과를 낸 모듈의 META["kisa"] 첫 코드로 분류한다. 코드를 둘 단 모듈(예: 입력값
# 넣어 보기 XS·SI)도 결과를 두 번 세지 않으려는 것이다 — 합이 전체 건수와 맞아야 한다.
# 코드가 없는 모듈(포트 확인 등)의 결과는 '분류 없음' 으로 따로 센다.

from . import standards  # noqa: E402
from .db import STATUSES  # noqa: E402


def _in(ids):
    return ",".join("?" * len(ids)) or "NULL"


def activity(db, targets):
    """맨 위 전체 숫자 — 우리가 얼마나 진단했고 무엇이 남았는지."""
    ids = [t["id"] for t in targets]
    m = _in(ids)
    one = lambda sql: db.execute(sql.format(m=m), ids).fetchone()[0] or 0  # noqa: E731
    return {
        "targets": len(ids),
        "findings": one("SELECT COUNT(*) FROM findings WHERE target_id IN ({m})"),
        # 참고(info)는 '여기 이런 게 있다' 는 메모다 — 취약점 수에 섞으면 숫자가 부풀어 보인다
        "info": one("SELECT COUNT(*) FROM findings WHERE target_id IN ({m}) AND severity = 'info'"),
        "false": one("SELECT COUNT(*) FROM findings WHERE target_id IN ({m}) AND status = 'false_positive'"),
        "open": one("SELECT COUNT(*) FROM findings WHERE target_id IN ({m}) AND status NOT IN ('fixed', 'false_positive')"),
        "runs": one("SELECT COUNT(*) FROM runs WHERE target_id IN ({m})"),
        "modules_used": one("SELECT COUNT(DISTINCT module_id) FROM runs WHERE target_id IN ({m})"),
        "requests": one("SELECT COUNT(*) FROM exchanges WHERE target_id IN ({m})"),
        "endpoints": one("SELECT COUNT(DISTINCT target_id || ' ' || url) FROM points WHERE target_id IN ({m})"),
        "params": one("SELECT COUNT(*) FROM points WHERE target_id IN ({m}) AND param != ''"),
    }


def breakdown(db, targets, modules):
    """유형(OWASP 2025)·항목(KISA 21)·처리 상태별 건수와 점검 범위."""
    ids = [t["id"] for t in targets]
    m = _in(ids)
    ran = {r[0] for r in db.execute(f"SELECT DISTINCT module_id FROM runs WHERE target_id IN ({m})", ids)}
    rows = db.execute(f"SELECT module_id, severity, status, COUNT(*) c FROM findings "
                      f"WHERE target_id IN ({m}) GROUP BY module_id, severity, status", ids).fetchall()

    def primary(mid):
        mod = modules.get(mid)
        return mod.kisa[0] if mod and mod.kisa else ""

    owasp = {k: {s: 0 for s in SEVERITIES} for k, _ in standards.OWASP_2025}
    unclassified = {s: 0 for s in SEVERITIES}
    kisa_found = {c: 0 for c in standards.KISA}
    by_status = {k: 0 for k in STATUSES}
    for r in rows:
        if r["status"] in by_status:
            by_status[r["status"]] += r["c"]
        if r["status"] in CLOSED or r["severity"] not in SEVERITIES:
            continue
        code = primary(r["module_id"])
        if code:
            owasp[standards.KISA[code][1]][r["severity"]] += r["c"]
            kisa_found[code] += r["c"]
        else:
            unclassified[r["severity"]] += r["c"]

    def state(mods, found):
        if found:
            return "found"
        if not mods:
            return "none"
        return "clear" if any(x.id in ran for x in mods) else "ready"

    owasp_rows = []
    for key, name in standards.OWASP_2025:
        mods = [x for x in modules.values() if key in x.owasp]
        total = sum(owasp[key].values())
        owasp_rows.append({"key": key, "name": name, "counts": owasp[key], "total": total,
                           "state": state(mods, total), "modules": len(mods)})
    top = max([r["total"] for r in owasp_rows] + [sum(unclassified.values()), 1])
    for r in owasp_rows:
        r["segments"] = [{"severity": s, "n": r["counts"][s], "pct": r["counts"][s] * 100 / top}
                         for s in SEVERITIES if r["counts"][s]]
    un_total = sum(unclassified.values())

    kisa_rows = []
    for code, (name, okey) in standards.KISA.items():
        mods = [x for x in modules.values() if code in x.kisa]
        kisa_rows.append({"code": code, "name": name, "owasp": okey, "found": kisa_found[code],
                          "modules": [x.name for x in mods], "state": state(mods, kisa_found[code])})
    cover = {s: sum(1 for r in kisa_rows if r["state"] == s) for s in ("found", "clear", "ready", "none")}

    status_total = sum(by_status.values()) or 1
    return {
        "owasp": owasp_rows,
        "unclassified": {"total": un_total, "segments": [
            {"severity": s, "n": unclassified[s], "pct": unclassified[s] * 100 / top} for s in SEVERITIES if unclassified[s]]},
        "kisa": kisa_rows,
        "kisa_cover": cover,
        "status": [{"status": k, "label": v, "n": by_status[k], "pct": by_status[k] * 100 / status_total}
                   for k, v in STATUSES.items()],
    }


# ── 진단 일정(11-20 추가): 프로젝트 주차·요일별 진단 활동을 GitHub 잔디처럼 색 농도로 ──
#
# 한 칸이 하루, 가로가 주차(1주차~), 세로가 요일(월~일)이다. 주는 월요일부터 센다.
# 새싹에듀는 10-12(월) 주를 1주차로 7주 — 최종보고회 11-23(월)이 7주차 첫날이다(사용자 결정 11-20).
# 마지막 날(end) 뒤의 칸은 기간 밖이라 비워 둔다.
# 기간은 프로젝트 팩의 PROJECT["schedule"] 에서 온다. 보고회 날(중간·최종)은 칸을 그 색으로 채운다.
# 시각은 KST ISO 로 저장돼 있어(core.now_iso) 앞 10글자가 곧 KST 날짜다.

from datetime import date, timedelta  # noqa: E402

WEEKDAYS = "월화수목금토일"


def _daily(db, sql, ids):
    m = _in(ids)
    return {r[0]: r[1] for r in db.execute(sql.format(m=m), ids)}


def _work(runs, requests, found, touched=0):
    """그날 작업량 한 숫자. 모듈 실행을 기본으로, 결과와 요청을 조금씩 얹는다.
    퍼징 하루가 요청 수천 개라 요청을 그대로 더하면 다른 날이 다 옅어진다 — 100개를 실행 1번으로 친다.
    touched 는 그날 다시 확인된 결과·지점 점검 수 — 실행 없이 손댄 날도 비어 보이지 않게 조금 얹는다."""
    return runs + found + requests / 100 + touched / 10


WEEKEND_LEVEL = 1  # 주말은 '했다' 를 연한 한 단계로만 칠한다(사용자 결정 11-20)


def _levels(scores, weekend=()):
    """평일은 GitHub 잔디처럼 활동한 날끼리 4단계(사분위, 순위로 — 가장 많은 날 하나 때문에
    나머지가 옅어지지 않게). 주말은 했다/안 했다만 본다(사용자 결정 11-20)."""
    vals = sorted(v for k, v in scores.items() if v > 0 and k not in weekend)
    cut = [vals[int((len(vals) - 1) * q)] for q in (0.25, 0.5, 0.75)] if vals else [0, 0, 0]
    out = {}
    for k, v in scores.items():
        if v <= 0:
            out[k] = 0
        elif k in weekend:
            out[k] = WEEKEND_LEVEL
        else:
            out[k] = 1 + sum(v > c for c in cut)
    return out


def calendar(db, targets, schedule=None, today=None, weeks_n=None):
    today = today or date.today()
    schedule = schedule or {}
    end = date.fromisoformat(schedule["end"]) if schedule.get("end") else today
    start = date.fromisoformat(schedule["start"]) if schedule.get("start") else end - timedelta(days=48)
    weeks_n = weeks_n or schedule.get("weeks") or -(-((end - start).days + 1) // 7)

    ids = [t["id"] for t in targets]
    day = "substr({col}, 1, 10)"
    runs = _daily(db, f"SELECT {day.format(col='started_at')} d, COUNT(*) FROM runs WHERE target_id IN ({{m}}) GROUP BY d", ids)
    reqs = _daily(db, f"SELECT {day.format(col='created_at')} d, COUNT(*) FROM exchanges WHERE target_id IN ({{m}}) GROUP BY d", ids)
    found = _daily(db, f"SELECT {day.format(col='created_at')} d, COUNT(*) FROM findings WHERE target_id IN ({{m}}) GROUP BY d", ids)
    # 실행 없이 손댄 날: 결과가 다시 확인됐거나(last_seen) 지점을 점검한 날
    seen = _daily(db, f"SELECT {day.format(col='last_seen')} d, COUNT(*) FROM findings WHERE target_id IN ({{m}}) "
                      f"AND last_seen IS NOT NULL GROUP BY d", ids)
    checked = _daily(db, f"SELECT {day.format(col='pc.checked_at')} d, COUNT(*) FROM point_checks pc "
                         f"JOIN points p ON p.id = pc.point_id WHERE p.target_id IN ({{m}}) GROUP BY d", ids)
    first = start - timedelta(days=start.weekday())          # 그 주 월요일부터
    days = [first + timedelta(days=i) for i in range(weeks_n * 7)]
    scores = {d.isoformat(): _work(runs.get(d.isoformat(), 0), reqs.get(d.isoformat(), 0), found.get(d.isoformat(), 0),
                                   seen.get(d.isoformat(), 0) + checked.get(d.isoformat(), 0))
              for d in days}
    level = _levels(scores, weekend={d.isoformat() for d in days if d.weekday() >= 5})
    # 팀 작업 기록(프로젝트 팩 schedule.worklog) — 진단 기록과 진한 쪽을 쓴다
    declared = {}
    for monday, row in (schedule.get("worklog") or {}).items():
        base = date.fromisoformat(monday)
        for i, v in enumerate(row[:7]):
            declared[(base + timedelta(days=i)).isoformat()] = max(0, min(4, int(v)))

    marks = {m["date"]: m for m in schedule.get("marks", [])}
    weeks = []
    for w in range(weeks_n):
        cells = []
        for d in days[w * 7:(w + 1) * 7]:
            key = d.isoformat()
            mk = marks.get(key, {})
            cells.append({
                "date": key, "md": d.strftime("%m-%d"), "wd": WEEKDAYS[d.weekday()],
                "runs": runs.get(key, 0), "requests": reqs.get(key, 0), "found": found.get(key, 0),
                "level": 0 if d > today else max(level.get(key, 0), declared.get(key, 0)),
                "declared": declared.get(key, 0), "in_period": start <= d <= end, "future": d > today,
                "mark": mk.get("label", ""), "kind": mk.get("kind", ""), "short": mk.get("short", ""),
                "today": d == today,
            })
        first = days[w * 7]
        weeks.append({"cells": cells, "label": f"{w + 1}주차", "from": first.strftime("%m/%d"),
                      "now": first <= today < first + timedelta(days=7)})

    active = [c for w in weeks for c in w["cells"] if c["level"]]
    top = max(active, key=lambda c: (scores[c["date"]], c["level"]), default=None)
    upcoming = sorted((k, v["label"]) for k, v in marks.items() if k >= today.isoformat())
    nxt = None
    if upcoming:
        k, v = upcoming[0]
        nxt = {"label": v, "md": k[5:], "days": (date.fromisoformat(k) - today).days}
    now_week = next((w["label"] for w in weeks if w["now"]), "")
    return {
        "weeks": weeks, "weekdays": [weeks[0]["cells"][i]["wd"] for i in range(7)] if weeks else [],
        "start": start.isoformat(), "end": end.isoformat(), "weeks_n": weeks_n, "now_week": now_week,
        "active_days": len(active), "top": top, "next": nxt,
        "total_runs": sum(c["runs"] for w in weeks for c in w["cells"]),
    }
