"""결과 탭 위쪽 그림에 쓰는 집계(11-20 기획 1단계).

① 요약 숫자 4개  ② 대상별 심각도 막대  ⑤ 처리 진행 막대.
'미조치' 는 조치됨·오탐을 뺀 것이다 — 심각도 카드가 원래 그렇게 셌다.
"""
from .core import SEVERITIES
from .db import STATUSES

CLOSED = ("fixed", "false_positive")


def _pct(n, total):
    return round(n * 100 / total, 1) if total else 0


def by_target(db, targets):
    """대상마다 미조치 심각도별 건수. 막대 길이는 가장 많은 대상을 100 으로 맞춘다 —
    대상끼리 길이로 비교할 수 있어야 한다."""
    counts = {t["id"]: {s: 0 for s in SEVERITIES} for t in targets}
    for r in db.execute("SELECT target_id, severity, COUNT(*) c FROM findings "
                        "WHERE status NOT IN (?, ?) GROUP BY target_id, severity", CLOSED):
        if r["target_id"] in counts and r["severity"] in SEVERITIES:
            counts[r["target_id"]][r["severity"]] = r["c"]
    biggest = max((sum(c.values()) for c in counts.values()), default=0)
    rows = []
    for t in targets:
        c = counts[t["id"]]
        total = sum(c.values())
        rows.append({"target": t, "total": total, "width": _pct(total, biggest),
                     "segments": [{"severity": s, "n": c[s], "pct": _pct(c[s], total)} for s in SEVERITIES if c[s]]})
    return rows


def progress(db, target_id):
    """한 대상의 처리 상태별 건수. 모의해킹 팀이 결과를 얼마나 검토했는지 본다."""
    c = {k: 0 for k in STATUSES}
    for r in db.execute("SELECT status, COUNT(*) c FROM findings WHERE target_id = ? GROUP BY status", [target_id]):
        if r["status"] in c:
            c[r["status"]] = r["c"]
    total = sum(c.values())
    return {"total": total, "reviewed_pct": _pct(total - c["open"], total),
            "segments": [{"status": k, "label": v, "n": c[k], "pct": _pct(c[k], total)} for k, v in STATUSES.items()]}


def headline(db, target_id, targets):
    """① 맨 윗줄 숫자 4개."""
    row = db.execute(
        "SELECT SUM(status NOT IN (?, ?)) open_n, "
        "SUM(status NOT IN (?, ?) AND severity IN ('critical', 'high')) top_n "
        "FROM findings WHERE target_id = ?", [*CLOSED, *CLOSED, target_id]).fetchone()
    scanned = db.execute("SELECT COUNT(DISTINCT target_id) FROM runs").fetchone()[0]
    return {"open": row["open_n"] or 0, "top": row["top_n"] or 0,
            "scanned": scanned, "targets": len(targets)}
