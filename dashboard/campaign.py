"""캠페인 — 팀이 후보 중에서 골라 전술 열에 놓고 선으로 잇는 공격 흐름.

수사보드의 '확인됨·제안' 은 대시보드가 늘어놓는 재료다. 캠페인은 그 재료로 **팀이 정한** 흐름이다.
그래서 노드는 무엇이든 팀이 놓은 것만, 선도 팀이 그은 것만 있다. 대시보드가 기법 사이를
자동으로 잇지 않는다(그 데이터를 갖고 있지 않다 — board.py 머리 주석).

노드 종류
    finding   딸깍이 결과 한 줄       ref = findings.id
    observed  관찰한 제품/버전        ref = "Apache Tomcat 10.1.1"
    cve       CVE 후보(NVD·팀)       ref = "CVE-2025-24813"
    module    아직 안 돌린 모듈        ref = 모듈 id
    manual    딸깍이 밖에서 한 단계     ref = "" (셸·C2·DB 백업 등. note 에 근거 문서)

노드는 놓을 때의 제목·상태를 **복사해 둔다**. 결과를 지우거나 다시 돌려도 발표용 흐름이 깨지지 않게.
선의 label 은 '앞 단계에서 얻어 다음 단계에 넘긴 것'(JWT_SECRET, ADMIN 토큰 …)을 적는 자리다.
"""
from datetime import datetime, timezone

from .attack import TACTIC_NAME, TACTIC_ORDER

KINDS = {"finding": "결과", "observed": "관찰한 버전", "cve": "CVE", "module": "모듈", "manual": "수동"}
STATUSES = ("확인", "코드 확인", "추정", "미확인")


def _now():
    return datetime.now(timezone.utc).isoformat()


def for_target(db, tid):
    return db.execute("SELECT * FROM campaigns WHERE target_id = ? ORDER BY id", [tid]).fetchall()


def create(db, tid, name, goal=""):
    cur = db.execute("INSERT INTO campaigns (target_id, name, goal, created_at) VALUES (?, ?, ?, ?)",
                     [tid, name.strip()[:80], goal.strip()[:200], _now()])
    db.commit()
    return cur.lastrowid


def state(db, cid):
    """화면이 그리는 전부: 캠페인, 노드, 선, 쓰인 전술 열."""
    c = db.execute("SELECT * FROM campaigns WHERE id = ?", [cid]).fetchone()
    if not c:
        return None
    nodes = [dict(r) for r in db.execute("SELECT * FROM campaign_nodes WHERE campaign_id = ? ORDER BY id", [cid])]
    edges = [dict(r) for r in db.execute("SELECT * FROM campaign_edges WHERE campaign_id = ? ORDER BY id", [cid])]
    for n in nodes:
        n["kind_label"] = KINDS.get(n["kind"], n["kind"])
    # 자리를 아직 안 정한 카드(-1)는 여기서 띠 안에 놓아 준다 — 화면이 빈 자리를 몰라도 되게
    blank = [n for n in nodes if n["x"] < 0 or n["y"] < 0]
    if blank:
        spots = {nid: (x, y) for nid, x, y in arrange(nodes)}
        for n in blank:
            n["x"], n["y"] = spots.get(n["id"], (0.0, float(TOP)))
        place(db, cid, [(n["id"], n["x"], n["y"]) for n in blank])
    return {"id": c["id"], "name": c["name"], "goal": c["goal"], "target_id": c["target_id"],
            "nodes": nodes, "edges": edges,
            "tactics": sorted({n["tactic"] for n in nodes}, key=lambda t: TACTIC_ORDER.get(t, 99))}


def _clean(kind, tactic, title, status):
    if kind not in KINDS:
        raise ValueError("노드 종류가 맞지 않습니다")
    if tactic not in TACTIC_NAME:
        raise ValueError("전술이 맞지 않습니다")
    if not (title or "").strip():
        raise ValueError("제목이 비었습니다")
    if status and status not in STATUSES:
        raise ValueError("상태는 확인·코드 확인·추정·미확인 중 하나입니다")


def add_node(db, cid, kind, tactic, title, ref="", sub="", status="", note="", x=None, y=None):
    _clean(kind, tactic, title, status)
    if kind != "manual" and ref:
        # 같은 것을 두 번 올리면 선이 어디로 가는지 헷갈린다 — 같은 열이면 그대로 둔다
        dup = db.execute("SELECT id FROM campaign_nodes WHERE campaign_id = ? AND kind = ? AND ref = ? AND tactic = ?",
                         [cid, kind, ref, tactic]).fetchone()
        if dup:
            return dup["id"]
    cur = db.execute(
        "INSERT INTO campaign_nodes (campaign_id, kind, ref, tactic, title, sub, status, note, x, y, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [cid, kind, str(ref)[:200], tactic, title.strip()[:200], (sub or "")[:300], status or "",
         (note or "")[:500], float(x) if x is not None else -1.0, float(y) if y is not None else -1.0, _now()])
    db.commit()
    return cur.lastrowid


def update_node(db, cid, nid, **kw):
    row = db.execute("SELECT * FROM campaign_nodes WHERE id = ? AND campaign_id = ?", [nid, cid]).fetchone()
    if not row:
        raise LookupError
    vals = {k: kw[k] for k in ("tactic", "status", "note", "title") if kw.get(k) is not None}
    _clean(row["kind"], vals.get("tactic", row["tactic"]), vals.get("title", row["title"]),
           vals.get("status", row["status"]))
    for k, v in vals.items():
        db.execute(f"UPDATE campaign_nodes SET {k} = ? WHERE id = ?", [v[:500], nid])
    # 자리는 글자가 아니다 — 자르지 않고 수로 넣는다(자유 배치, 11-22)
    for k in ("x", "y"):
        if kw.get(k) is not None:
            db.execute(f"UPDATE campaign_nodes SET {k} = ? WHERE id = ?", [float(kw[k]), nid])
    db.commit()


# ── 자리 ────────────────────────────────────────────────────
# 칸에 고정하지 않는다. 대신 전술마다 **띠**(세로 구역)를 두고, 카드가 놓인 x 로 어느 전술인지
# 정한다(11-22 사용자: 자유 배치여도 전술 구분은 보여야 한다). 정렬은 그 띠 안에 가지런히 쌓는다.
LANE_W = 260          # 전술 띠 하나의 너비
LANE_PAD = 20         # 띠 안쪽 여백
CARD_W = 220
ROW_H = 132           # 카드 한 장이 차지하는 세로
TOP = 54              # 띠 머리(전술 이름) 아래부터


def lane_x(tactic) -> float:
    """그 전술 띠의 왼쪽 x."""
    return TACTIC_ORDER.get(tactic, len(TACTIC_ORDER)) * LANE_W


def tactic_at(x) -> str:
    """x 가 어느 띠에 떨어지는가 → 전술. 보드 밖이면 양 끝 띠로 본다."""
    order = sorted(TACTIC_ORDER, key=lambda t: TACTIC_ORDER[t])
    i = int(max(0, min(len(order) - 1, (float(x) + CARD_W / 2) // LANE_W)))
    return order[i]


def arrange(nodes) -> list:
    """카드를 전술 띠 안에 가지런히 놓는다 → [(id, x, y)].

    같은 띠에 여럿이면 위에서부터 쌓고, 한 줄에 너무 길어지면 띠 안에서 두 줄로 나눈다.
    사람이 끌어 둔 자리는 '정렬' 을 누를 때만 바뀐다.
    """
    by_lane = {}
    for n in sorted(nodes, key=lambda n: (TACTIC_ORDER.get(n["tactic"], 99), n["id"])):
        by_lane.setdefault(n["tactic"], []).append(n)
    out = []
    for tactic, got in by_lane.items():
        left = lane_x(tactic) + LANE_PAD
        for i, n in enumerate(got):
            out.append((n["id"], float(left), float(TOP + i * ROW_H)))
    return out


def place(db, cid, spots):
    """[(id, x, y)] 를 한 번에 저장한다 — 정렬 단추가 쓴다."""
    for nid, x, y in spots:
        db.execute("UPDATE campaign_nodes SET x = ?, y = ? WHERE id = ? AND campaign_id = ?",
                   [float(x), float(y), nid, cid])
    db.commit()


def delete_node(db, cid, nid):
    db.execute("DELETE FROM campaign_nodes WHERE id = ? AND campaign_id = ?", [nid, cid])
    db.commit()


def add_edge(db, cid, src, dst, label=""):
    if src == dst:
        raise ValueError("같은 노드끼리는 잇지 않습니다")
    ids = {r["id"] for r in db.execute("SELECT id FROM campaign_nodes WHERE campaign_id = ? AND id IN (?, ?)",
                                         [cid, src, dst])}
    if ids != {src, dst}:
        raise LookupError
    db.execute("INSERT INTO campaign_edges (campaign_id, src, dst, label) VALUES (?, ?, ?, ?) "
               "ON CONFLICT (src, dst) DO UPDATE SET label = excluded.label",
               [cid, src, dst, (label or "").strip()[:120]])
    db.commit()


def update_edge(db, cid, eid, label):
    db.execute("UPDATE campaign_edges SET label = ? WHERE id = ? AND campaign_id = ?", [(label or "").strip()[:120], eid, cid])
    db.commit()


def delete_edge(db, cid, eid):
    db.execute("DELETE FROM campaign_edges WHERE id = ? AND campaign_id = ?", [eid, cid])
    db.commit()


def delete(db, cid):
    db.execute("DELETE FROM campaigns WHERE id = ?", [cid])
    db.commit()
