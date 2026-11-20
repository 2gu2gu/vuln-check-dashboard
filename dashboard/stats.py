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
