"""로그인해서 토큰 받기 — 손으로 curl 치고 복사해 붙이던 것을 화면에서 한다.

경로 조작·SQL 주입 같은 모듈은 로그인한 사용자여야 돌아간다. 지금까지는
터미널에서 로그인 요청을 보내고 응답에서 토큰을 꺼내 대상 탭에 붙여 넣어야 했다.

**비밀번호는 저장하지 않는다.** 받아서 한 번 보내고 버린다. DB 에도, 요청 기록에도
남기지 않는다(`record_request=False`).

**토큰은 가리지 않는다.** 자체 실습 환경이고 받자마자 curl 에 붙여 쓰는 일이 많은데,
가려 두면 맞게 들어갔는지 볼 수도, 복사해 쓸 수도 없다. 요청 기록에서만 `***` 로 가린다 —
거기는 나중에 발표 자료로 통째로 나가는 화면이라서다.

프로젝트 팩이 `PROJECT["login"]` 으로 어디에 무엇을 보낼지 적어 둔다. 앱 본체는
특정 서비스의 로그인 모양을 모른다.

    PROJECT["login"] = {
        "path": "/backend/login",
        "json": {"email": "{id}", "pw": "{secret}"},   # {id}·{secret} 이 입력값으로 바뀐다
        "token_keys": ["token", "data.token"],          # 응답에서 토큰을 찾을 자리
        "header": "Authorization", "prefix": "Bearer ",
        "roles": ["user_web"],                          # 이 역할의 대상에만 보인다
    }
"""
import json
import re

from . import core, scope


class LoginFailed(Exception):
    """로그인이 안 됐을 때. 메시지는 사람이 읽을 말로 적는다."""


def config_for(project, role: str = ""):
    """이 대상에 쓸 로그인 설정. 없으면 None."""
    cfg = getattr(project, "login", None) if project else None
    if not cfg:
        return None
    roles = cfg.get("roles") or []
    if roles and role and role not in roles:
        return None
    demo = (cfg.get("demo_accounts") or {}).get(role)
    if not demo:
        return cfg
    # 연습용 대상이면 넣을 값까지 들고 간다. 화면에서 그대로 보여 준다.
    out = dict(cfg)
    out["demo"] = demo
    return out


def _dig(blob, path: str):
    """'data.token' 처럼 점으로 이어진 자리를 찾아 들어간다."""
    cur = blob
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur if isinstance(cur, str) and cur.strip() else None


def _places(blob, prefix="", depth=0):
    """응답에 **어떤 자리가 있었는지** 이름만 모은다. 값은 담지 않는다 — 토큰이 섞인다."""
    if not isinstance(blob, dict) or depth > 2:
        return []
    out = []
    for k, v in list(blob.items())[:12]:
        here = f"{prefix}{k}"
        out.append(here + ("" if isinstance(v, (str, int, float, bool, type(None))) else "…"))
        out += _places(v, here + ".", depth + 1)
    return out[:24]


def find_token(body: str, keys):
    """응답에서 토큰을 꺼낸다. 어디 있는지는 팩이 적어 둔 자리만 본다."""
    try:
        blob = json.loads(body)
    except ValueError:
        raise LoginFailed("응답이 JSON 이 아닙니다 — 로그인 주소가 맞는지 확인하세요")
    for key in keys or ("token",):
        got = _dig(blob, key)
        if got:
            # 'Bearer eyJ…' 처럼 접두사까지 들어 있으면 떼어 낸다 — 붙이는 쪽에서 또 붙인다
            return re.sub(r"^\s*Bearer\s+", "", got.strip())
    where = " · ".join(keys or ("token",))
    had = _places(blob)
    # 어디 있는지 모르면 고칠 수가 없다. 자리 '이름' 만 보여 준다(값은 안 보여 준다).
    seen = ("\n응답에 있던 자리: " + " · ".join(had)) if had else ""
    raise LoginFailed(f"응답에 토큰이 없습니다. 찾아본 자리: {where}{seen}")


def fetch_token(target_url: str, cfg: dict, ident: str, secret: str, hosts=None) -> str:
    """로그인 요청을 한 번 보내고 토큰만 돌려준다. 비밀번호는 어디에도 남기지 않는다."""
    if not ident or not secret:
        raise LoginFailed("아이디와 비밀번호를 모두 넣어 주세요")
    url = core.join(target_url, cfg.get("path") or "/login")
    if hosts is not None:
        scope.ensure_in_scope(url, hosts)          # 등록된 그 대상 밖으로 못 나간다

    shape = cfg.get("json") or {"email": "{id}", "password": "{secret}"}
    body = {k: v.replace("{id}", ident).replace("{secret}", secret) if isinstance(v, str) else v
            for k, v in shape.items()}
    r = core.fetch(url, method="POST",
                   raw_body=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                   content_type="application/json",
                   record_request=False,          # 비밀번호가 실린 본문은 안 남긴다
                   record_body=False)             # 응답에 토큰이 들어 있다
    if r.status >= 400:
        raise LoginFailed(f"로그인이 거절됐습니다 (응답 {r.status}) — 계정이 맞는지 확인하세요")
    # 본문이 아니라 응답 헤더(Authorization: Bearer …)로 토큰을 주는 서버가 있다(새싹에듀 /backend/login)
    got = r.header(cfg.get("header") or "Authorization")
    if got and got.strip():
        return re.sub(r"^\s*Bearer\s+", "", got.strip())
    return find_token(r.body, cfg.get("token_keys"))


def header_line(cfg: dict, token: str) -> str:
    """대상의 인증 헤더에 넣을 한 줄."""
    return "%s: %s%s" % (cfg.get("header") or "Authorization", cfg.get("prefix") or "", token)
