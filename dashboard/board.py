"""수사보드 — 어디까지 왔고 다음에 무엇을 할지.

전에는 '시나리오' 탭이 결과를 전술별로 **늘어놓기만** 했다. 흐름이 아니라 묶음이었고,
"그래서 다음은?" 에 답이 없었다.

이제 전술을 공격 진행 순서로 세우고 칸마다 두 가지를 따로 담는다.

    확인됨   실제로 돌려서 나온 결과
    제안     그 전술을 다루는 모듈인데 아직 안 돌린 것

**이 둘을 섞지 않는 것이 요점이다.** 제안을 결과처럼 그려 두면 발표에서
"이건 실제로 한 건가요?" 에 답을 못 한다. 퍼징 모듈에서 '씨앗·확장' 과 '단서' 를
가른 것과 같은 이유다.

## 지어내지 않는 것

ATT&CK 에는 "T1190 다음은 T1059" 같은 기법 간 연결이 따로 있지만 우리는 그 데이터를
갖고 있지 않다. 그래서 **쓰지 않는다.** 여기서 쓰는 근거는 넷뿐이다.

    전술 순서       ATT&CK 의 kill-chain 순서 (dashboard/attack.py)
    모듈의 전술     META["attack"] 에 모듈이 직접 적어 둔 것
    이 대상의 결과   우리가 실제로 찾은 것
    모듈이 준비됐는지 META["needs"] — 왜 못 돌리는지까지 말해 준다
"""
from .attack import TACTICS, TACTIC_NAME
from .registry import STAGE_LABEL

# 모듈을 왜 지금 못 돌리는지. 추측하지 않고 아는 것만 적는다.
READY, BLOCKED, ELSEWHERE = "ready", "blocked", "elsewhere"


def _why_not(mod, needs_rows):
    """(상태, 한 줄 설명). 돌릴 수 있으면 (READY, '')."""
    missing = [n for n in needs_rows if n["required"] and n["ready"] is False]
    if missing:
        n = missing[0]
        return BLOCKED, f"{n['label']}{(' ' + n['name']) if n['name'] else ''} 가 없습니다"
    if mod.stage == "probe":
        return ELSEWHERE, "표면 탭에서 지점을 골라 돌립니다"
    if mod.stage == "tool":
        return ELSEWHERE, "도구 탭에서 값을 넣고 돌립니다"
    return READY, ""


def build(findings, modules, tech_tactic, needs_of):
    """[{tactic, name, done, found, suggest}] — 전술 순서대로.

    findings  이 대상의 결과 행들(미확인·확인됨)
    modules   이 대상에 쓸 수 있는 모듈들
    tech_tactic  기법 → 전술
    needs_of(mod)  그 모듈의 준비 상태
    """
    found = {}
    used = {}
    for f in findings:
        tac = tech_tactic.get(f["technique"], "TA0043")
        found.setdefault(tac, []).append(f)
        used.setdefault(tac, set()).add(f["module_id"])

    covers = {}
    for m in modules:
        for a in m.attack:
            covers.setdefault(a.get("tactic", ""), []).append(m)

    rows = []
    for tid, _en, ko in TACTICS:
        hits = found.get(tid, [])
        # 이미 그 전술에서 결과를 낸 모듈은 제안하지 않는다 — 한 번 더 돌리라는 말이 되어 버린다
        pool = [m for m in covers.get(tid, []) if m.id not in used.get(tid, set())]
        if not hits and not pool:
            continue                      # 결과도 없고 쓸 모듈도 없는 전술은 빼 둔다
        suggest = []
        for m in sorted(pool, key=lambda x: (bool(x.project), x.name)):
            state, why = _why_not(m, needs_of(m))
            suggest.append({"mod": m, "state": state, "why": why,
                            "stage": STAGE_LABEL[m.stage]})
        rows.append({"tactic": tid, "name": ko, "done": bool(hits),
                     "found": hits, "suggest": suggest})
    return rows


def summary(rows):
    """한 줄 요약 — 어디까지 왔는지."""
    done = [r for r in rows if r["done"]]
    nxt = next((r for r in rows if not r["done"] and
                any(s["state"] == READY for s in r["suggest"])), None)
    return {
        "tactics": len(rows),
        "done": len(done),
        "last": done[-1]["name"] if done else "",
        "next": nxt["name"] if nxt else "",
        "next_mods": [s["mod"].name for s in nxt["suggest"] if s["state"] == READY][:3] if nxt else [],
        "blocked": sum(1 for r in rows for s in r["suggest"] if s["state"] == BLOCKED),
    }
