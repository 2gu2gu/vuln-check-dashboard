"""모듈이 돌아가려면 미리 준비해야 하는 것(needs).

파라미터는 실행할 때 그 자리에서 채우는 값이고, needs 는 **화면 밖에서 미리 해 둬야 하는 것**이다.
로그인 토큰, 환경변수, 칼리에서 먼저 돌려야 하는 도구 같은 것들.
이것이 안 보이면 실행 → 실패 → 왜인지 찾기를 반복하게 되므로, 실행 버튼 옆에 미리 보여 준다.

모듈 META 에 이렇게 적는다.

    "needs": [
        {"kind": "auth_header", "name": "Authorization",
         "why": "로그인한 사용자만 자료를 내려받을 수 있습니다",
         "how": "대상 탭 → 인증 헤더에 'Authorization: Bearer <토큰>' 한 줄"},
    ]

kind 별로 '지금 준비됐는지'를 확인할 수 있는 것과 없는 것이 있다.

    auth_header  대상의 인증 헤더에 그 이름이 있는지 — 확인 가능
    env          환경변수가 비어 있지 않은지 — 확인 가능
    wordlist     쓸 수 있는 사전이 하나라도 있는지 — 확인 가능
    tool         칼리 등에서 사람이 먼저 돌려야 하는 도구 — 확인 불가, 안내만
    account      테스트 계정 — 확인 불가, 안내만

`required` 를 False 로 두면 없어도 돌아가되 결과가 줄어든다는 뜻이다(기본 True).
"""
import os

KINDS = ("auth_header", "env", "wordlist", "tool", "account")

KIND_LABEL = {
    "auth_header": "인증 헤더",
    "env": "환경변수",
    "wordlist": "사전",
    "tool": "바깥 도구",
    "account": "테스트 계정",
}

# 확인할 수 없는 것 — 사람이 준비했는지 대시보드는 알 수 없다
UNCHECKABLE = ("tool", "account")


def validate(needs) -> list:
    """META 의 needs 를 검사해 정규화한다. 모듈 등록 때 불린다."""
    out = []
    for n in needs or []:
        if not isinstance(n, dict):
            raise ValueError(f"needs 항목은 dict 여야 합니다: {n!r}")
        kind = n.get("kind")
        if kind not in KINDS:
            raise ValueError(f"needs 의 kind 는 {KINDS} 중 하나여야 합니다 (받은 값: {kind!r})")
        if not n.get("why") or not n.get("how"):
            raise ValueError(f"needs 항목에는 why(왜 필요한지)와 how(어떻게 준비하는지)가 있어야 합니다: {n!r}")
        if kind in ("auth_header", "env") and not n.get("name"):
            raise ValueError(f"{kind} 에는 name 이 있어야 합니다: {n!r}")
        out.append({"kind": kind, "name": n.get("name", ""), "why": n["why"], "how": n["how"],
                    "required": bool(n.get("required", True))})
    return out


def _is_ready(need, header_names) -> bool:
    kind = need["kind"]
    if kind == "auth_header":
        return need["name"].lower() in {h.lower() for h in header_names}
    if kind == "env":
        return bool(os.environ.get(need["name"], "").strip())
    if kind == "wordlist":
        from dashboard import wordlists
        return bool(wordlists.available())
    return False


def check(mod, header_names=()) -> list:
    """모듈의 needs 에 '지금 준비됐는지'를 붙여 돌려준다.

    ready 는 True(준비됨) · False(아직) · None(확인할 수 없음) 세 가지다.
    """
    out = []
    for need in getattr(mod, "needs", []) or []:
        ready = None if need["kind"] in UNCHECKABLE else _is_ready(need, header_names)
        out.append({**need, "ready": ready, "label": KIND_LABEL[need["kind"]]})
    return out


def blocking(mod, header_names=()) -> list:
    """없으면 돌려도 실패할 것들. 확인할 수 없는 것은 막지 않는다."""
    return [n for n in check(mod, header_names) if n["required"] and n["ready"] is False]
