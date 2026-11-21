"""대상의 JWT 를 뜯어 보고, 손댄 토큰이 그대로 통하는지 확인한다.

노션 '웹 서비스 취약점 목록' 의 AUTH 묶음에 'JWT 토큰 폐기 메커니즘 부재' 와 '임의로 JWT 발급 후
계정탈취' 가 있다. 토큰 자체를 보는 점검은 요청을 거의 쓰지 않고 바로 드러나는 것이 많다.

  1. 뜯어 보기(요청 없음)  alg·exp·민감 클레임. 서명을 뺀 토큰, alg 를 none 으로 바꾼 토큰을 만들 재료다
  2. 손댄 토큰 보내기       확인 주소에 ① 원래 ② 서명만 바꾼 것 ③ alg=none ④ 클레임을 올린 것을 보낸다
                           원래만 2xx 면 서명을 보고 있는 것이고, 손댄 것도 2xx 면 서명을 안 보는 것이다.
                           **먼저 토큰을 아예 빼고 한 번 보낸다** — 그것도 2xx 로 같은 것이 오면 그 주소는
                           애초에 로그인을 안 보는 자리다. 거기서는 무엇을 보내도 통하니 '서명 검증 없음' 이
                           아니다(11-21: 화면 라우트를 2xx 로 읽어 오탐 81건을 만든 것과 같은 뿌리)

**서명 검증을 안 하는 서버에서는 ④ 로 관리자가 된다.** 그래서 ④ 는 role·auth·authority 같은 클레임을
올려 보고 2xx 가 오면 그 자리에서 취약으로 적는다.

읽기(GET)만 보낸다. 토큰 값은 가리지 않는다 — 자체 실습 환경이고, 가리면 맞는 토큰인지 확인할 수 없다.
"""
import base64
import json
import time

from dashboard import core
from dashboard.core import Finding

META = {
    "id": "jwt_probe",
    "name": "JWT 토큰 점검",
    "category": "인증·권한",
    "kisa": ["IA", "IS"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "AUTH",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "kind": "active",
    "stage": "check",
    "severity": "high",
    # JWT 는 SAML 이 아니라서 하위 기법(.002)이 아니라 상위 T1606 이다. T1548 은 호스트 권한 제어라 뺐다
    "attack": [{"tactic": "TA0006", "technique": "T1606", "name": "Forge Web Credentials"}],
    "description": "대상 인증 헤더의 **JWT 를 뜯어** alg·만료·민감 클레임을 보고, 확인 주소에 "
                   "**서명만 바꾼 토큰·alg=none 토큰·권한 클레임을 올린 토큰**을 보내 그대로 통하는지 봅니다. "
                   "통하면 서명 검증이 없는 것이고, 그 자리에서 계정 탈취가 됩니다.",
    "needs": [
        {"kind": "account", "required": True,
         "why": "대상 인증 헤더에 들어 있는 JWT 를 뜯어 보는 점검입니다",
         "how": "대상 탭의 **2. 인증** 에서 로그인해 토큰을 받거나 Bearer 를 직접 넣습니다"},
    ],
    "params": [
        {"name": "token", "need": "optional", "label": "토큰(비우면 대상 인증 헤더에서 찾음)", "default": ""},
        {"name": "verify_url", "need": "optional", "label": "확인 주소 (로그인해야 열리는 GET 주소)", "default": "",
         "placeholder": "https://sesacedu.store/backend/mypage",
         "help": "비우면 뜯어 보기까지만 합니다. 넣으면 손댄 토큰을 실제로 보내 봅니다."},
        {"name": "logout_url", "need": "optional", "label": "로그아웃 주소 (POST) — 폐기되는지 볼 때만", "default": "",
         "placeholder": "https://sesacedu.store/backend/auth/logout",
         "help": "로그아웃한 뒤 **같은 토큰** 으로 확인 주소를 다시 읽습니다. 열리면 폐기 장치가 없는 것입니다. "
                 "**이 토큰의 세션이 끊어집니다** — 넣으면 그 뜻으로 보고 실행합니다."},
    ],
}
SIGN = ("토큰을 받을 때마다 **서명을 검증** 하고(alg 를 서버가 정한 하나로 고정, 토큰의 alg 를 믿지 않음), "
        "만료(exp)를 짧게 두며, 로그아웃·비밀번호 변경 때 토큰을 무효로 만듭니다(서버 쪽 폐기 목록이나 짧은 "
        "접근 토큰 + 폐기 가능한 갱신 토큰). 권한은 토큰의 클레임이 아니라 서버가 저장소에서 다시 읽어 정합니다.")
# 권한을 올려 볼 클레임 이름과 올릴 값 — 새싹에듀는 auth 1·2·3 으로 학생·강사·관리자를 가른다
RAISE = {"role": "ADMIN", "auth": 3, "authority": "ROLE_ADMIN", "roles": ["ADMIN"], "isAdmin": True}
SENSITIVE = ("password", "pw", "passwd", "secret", "ssn", "card", "phone", "mobile", "email", "resident")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def split(token: str):
    """JWT → (헤더 dict, 페이로드 dict, 서명 문자열). JWT 가 아니면 None."""
    bits = (token or "").strip().split(".")
    if len(bits) != 3:
        return None
    try:
        head = json.loads(_unb64(bits[0]))
        body = json.loads(_unb64(bits[1]))
    except (ValueError, TypeError):
        return None
    if not isinstance(head, dict) or not isinstance(body, dict):
        return None
    return head, body, bits[2]


def find_token(params) -> str:
    """설정 칸에 적힌 토큰, 없으면 대상 인증 헤더에서 JWT 모양을 찾는다."""
    given = (params.get("token") or "").strip()
    if given:
        return given.split()[-1]
    for value in core.auth_headers().values():
        for word in value.replace(";", " ").replace("=", " ").split():
            if split(word):
                return word
    return ""


def remake(head: dict, body: dict, signature: str) -> str:
    return f"{_b64(json.dumps(head, separators=(',', ':')).encode())}." \
           f"{_b64(json.dumps(body, separators=(',', ':')).encode())}.{signature}"


def variants(head: dict, body: dict, signature: str):
    """손대 볼 토큰들 → [(설명, 토큰, 무엇을 뜻하는가)]."""
    flip = signature[:-1] + ("a" if signature[-1:] != "a" else "b") if signature else "x"
    raised = {**body, **{k: v for k, v in RAISE.items() if k in body}}
    out = [
        ("서명만 바꾼 토큰", remake(head, body, flip), "서명을 보지 않는다"),
        ("서명을 뺀 토큰", remake(head, body, ""), "서명 없이도 받는다"),
        ("alg=none 토큰", remake({**head, "alg": "none"}, body, ""), "토큰이 적은 alg 를 그대로 믿는다"),
    ]
    if raised != body:
        out.append(("권한 클레임을 올린 토큰", remake(head, raised, flip),
                    "서명을 안 보는 데다 권한을 토큰에서 읽는다 — 그 자리에서 관리자가 된다"))
    return out


def run(target, params):
    out = []
    token = find_token(params)
    if not token:
        return [Finding(title="JWT 를 찾지 못했습니다", severity="info", location=target.url,
                        evidence="대상 인증 헤더에 JWT 모양(점 두 개로 나뉜 세 토막)이 없습니다. "
                                 "대상 탭 '2. 인증' 에 토큰을 넣거나 이 모듈의 토큰 칸에 붙여 넣으세요.",
                        recommendation="")]
    got = split(token)
    if not got:
        return [Finding(title="JWT 모양이 아닙니다", severity="info", location=target.url,
                        evidence=f"받은 값: {core.excerpt(token, 200)}", recommendation="")]
    head, body, signature = got
    where = f"{target.url} (인증 헤더의 토큰)"
    shown = json.dumps({"header": head, "payload": body}, ensure_ascii=False, indent=2)

    # 1. 뜯어 보기 — 요청을 보내지 않는다
    alg = str(head.get("alg", "")).lower()
    if alg in ("none", ""):
        out.append(Finding(title="JWT 가 서명 없이 쓰이고 있습니다(alg=none)", severity="high", location=where,
                           evidence=shown, recommendation=SIGN, technique="T1606"))
    exp = body.get("exp")
    if exp is None:
        out.append(Finding(title="JWT 에 만료(exp)가 없습니다", severity="medium", location=where,
                           evidence=shown + "\n\nexp 클레임이 없어 한 번 새면 계속 쓸 수 있습니다.",
                           recommendation=SIGN, technique="T1606"))
    elif isinstance(exp, (int, float)):
        left = int(exp - time.time())
        if left <= 0:
            # 11-20 실측: 대상에 넣어 둔 토큰이 5시간 전에 끝나 있어 인증이 필요한 점검이 전부 ① 에서 멈췄다.
            # 그때 아무 말이 없으면 '왜 안 되는지' 를 사람이 알 수 없다. 가장 먼저 말해 준다.
            out.append(Finding(
                title="대상에 넣어 둔 JWT 가 이미 만료됐습니다", severity="info", location=where,
                evidence=shown + f"\n\nexp = {int(exp)} — {-left // 60}분 전에 끝났습니다.\n"
                                 "이 토큰으로는 인증이 필요한 점검(인증·인가, IDOR, 업로드)이 모두 ① 단계에서 "
                                 "멈춥니다. 대상 탭 '2. 인증' 에서 토큰을 새로 받으세요.",
                recommendation=""))
        elif left > 86400:
            out.append(Finding(title="JWT 만료가 너무 깁니다", severity="low", location=where,
                               evidence=shown + f"\n\nexp 까지 {left // 3600}시간 남았습니다.",
                               recommendation=SIGN, technique="T1606"))
    leaked = [k for k in body if any(s in k.lower() for s in SENSITIVE)]
    if leaked:
        out.append(Finding(title="JWT 본문에 민감한 클레임", severity="low", location=where,
                           evidence=shown + f"\n\n민감한 클레임: {', '.join(leaked)}\n"
                                    "JWT 본문은 서명만 붙은 것이고 **암호가 아니다** — 누구나 읽는다.",
                           recommendation="토큰 본문에는 식별자만 넣고 개인정보는 넣지 않습니다.", technique="T1606"))

    # 2. 손댄 토큰 보내기 — 확인 주소가 있을 때만
    url = (params.get("verify_url") or "").strip()
    if not url:
        out.append(Finding(title="토큰을 뜯어 보기까지만 했습니다", severity="info", location=where,
                           evidence=shown + "\n\n확인 주소를 넣으면 서명만 바꾼 토큰·alg=none 토큰을 실제로 보내 "
                                            "서명 검증이 있는지 봅니다.", recommendation=""))
        return out
    name = next(iter(core.auth_headers()), "Authorization")
    base = core.fetch(url, headers={name: f"Bearer {token}"}, auth=False)
    lines = [f"원래 토큰: GET {url} → {base.status} · {len(base.body)}B"]
    if base.status not in range(200, 300):
        lines.append(f"원래 토큰으로도 {base.status} — 확인 주소가 맞는지 보세요(로그인해야 열리는 GET 주소여야 합니다)")
        out.append(Finding(title="확인 주소에서 원래 토큰이 통하지 않습니다", severity="info", location=url,
                           evidence="\n".join(lines), recommendation="", response=base))
        return out
    # 토큰을 **아예 빼고** 같은 곳을 한 번 읽는다. 그래도 열리면 그 주소는 로그인을 안 보는 자리고,
    # 손댄 토큰이 통하는 것은 서명을 안 봐서가 아니다. 뒤의 폐기 확인도 같은 잣대를 쓰니 여기서 멈춘다.
    bare = core.fetch(url, auth=False)
    lines.append(f"토큰을 빼고: → {bare.status} · {len(bare.body)}B")
    if bare.status in range(200, 300) and bare.body == base.body:
        lines.append("  토큰이 없어도 **같은 것이 열린다** — 이 주소는 로그인을 보지 않는다")
        out.append(Finding(
            title="확인 주소가 토큰을 보지 않습니다", severity="info", location=url,
            evidence="\n".join(lines) + "\n\n여기서는 무엇을 보내도 통하니 서명을 보는지 알 수 없습니다. "
                     "**로그인해야만 열리는 GET 주소**(내 정보, 내 주문 같은 것)를 확인 주소로 넣으세요. "
                     "HAR 에서 Authorization 을 달고 나간 요청의 주소가 그것입니다.",
            recommendation="", response=bare))
        return out

    for kind, bad, means in variants(head, body, signature):
        r = core.fetch(url, headers={name: f"Bearer {bad}"}, auth=False)
        lines.append(f"{kind}: → {r.status} · {len(r.body)}B")
        if r.status in range(200, 300):
            lines.append(f"  통했다 — {means}")
            out.append(Finding(
                title=f"JWT 서명 검증 없음 — {kind}이 통함", severity="critical" if "권한" in kind else "high",
                location=url, evidence="\n".join(lines) + f"\n\n보낸 토큰:\n{bad}\n\n원래 토큰 내용:\n{shown}",
                recommendation=SIGN, technique="T1606", response=r))
            break
    else:
        lines.append("손댄 토큰은 모두 막혔다 — 서명 검증이 있다")
        out.append(Finding(title="JWT 서명 검증은 있습니다", severity="info", location=url,
                           evidence="\n".join(lines), recommendation="", response=base))

    # 3. 폐기되는가 — 로그아웃한 뒤 같은 토큰으로 다시 읽어 본다(주소를 적었을 때만)
    bye = (params.get("logout_url") or "").strip()
    if bye:
        lo = core.fetch(bye, method="POST", headers={name: f"Bearer {token}"}, auth=False)
        again = core.fetch(url, headers={name: f"Bearer {token}"}, auth=False)
        told = [f"로그아웃: POST {bye} → {lo.status}",
                f"같은 토큰으로 다시: GET {url} → {again.status} · {len(again.body)}B (로그아웃 전 {base.status} · {len(base.body)}B)"]
        if again.status in range(200, 300):
            told.append("로그아웃 뒤에도 같은 토큰이 통한다 — 서버에 폐기 장치가 없다")
            out.append(Finding(
                title="JWT 폐기 장치 없음 — 로그아웃 뒤에도 토큰이 통함", severity="high", location=url,
                evidence="\n".join(told) + f"\n\n토큰:\n{token}",
                recommendation=SIGN, technique="T1606", response=again))
        else:
            told.append(f"로그아웃 뒤에는 {again.status} — 폐기 장치가 있다")
            out.append(Finding(title="JWT 폐기 장치는 있습니다", severity="info", location=url,
                               evidence="\n".join(told), recommendation="", response=again))
    return out
