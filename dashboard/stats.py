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


# ── 진단 통계(11-20 추가): 맨 위 전체 숫자 · 유형별 · 주요정보통신기반시설 항목별 · 상태별 · 모듈별 ──
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
        "open": one("SELECT COUNT(*) FROM findings WHERE target_id IN ({m}) AND status NOT IN ('fixed', 'false_positive')"),
        "runs": one("SELECT COUNT(*) FROM runs WHERE target_id IN ({m})"),
        "modules_used": one("SELECT COUNT(DISTINCT module_id) FROM runs WHERE target_id IN ({m})"),
        "requests": one("SELECT COUNT(*) FROM exchanges WHERE target_id IN ({m})"),
        "endpoints": one("SELECT COUNT(DISTINCT target_id || ' ' || url) FROM points WHERE target_id IN ({m})"),
        "params": one("SELECT COUNT(*) FROM points WHERE target_id IN ({m}) AND param != ''"),
    }


def breakdown(db, targets, modules):
    """유형(OWASP 2025)·항목(KISA 21)·처리 상태·모듈별 건수와 점검 범위."""
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
    by_module = {}
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
        by_module[r["module_id"]] = by_module.get(r["module_id"], 0) + r["c"]

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
    mod_top = sorted(by_module.items(), key=lambda kv: -kv[1])[:6]
    mod_max = mod_top[0][1] if mod_top else 1
    return {
        "owasp": owasp_rows,
        "unclassified": {"total": un_total, "segments": [
            {"severity": s, "n": unclassified[s], "pct": unclassified[s] * 100 / top} for s in SEVERITIES if unclassified[s]]},
        "kisa": kisa_rows,
        "kisa_cover": cover,
        "status": [{"status": k, "label": v, "n": by_status[k], "pct": by_status[k] * 100 / status_total}
                   for k, v in STATUSES.items()],
        "modules": [{"id": mid, "name": modules[mid].name if mid in modules else mid, "n": n, "pct": n * 100 / mod_max}
                    for mid, n in mod_top],
    }
