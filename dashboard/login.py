"""로그인해서 토큰 받기 — 손으로 curl 치고 복사해 붙이던 것을 화면에서 한다.

경로 조작·SQL 주입 같은 모듈은 로그인한 사용자여야 돌아간다. 지금까지는
터미널에서 로그인 요청을 보내고 응답에서 토큰을 꺼내 대상 탭에 붙여 넣어야 했다.

**비밀번호는 저장하지 않는다.** 받아서 한 번 보내고 버린다 — DB 에 남지 않는다.
다만 **요청 기록에는 보낸 그대로 남는다**(2026-11-07부터). 자체 실습 환경이고, 무엇을
보냈는지 못 보는 기록은 증거로 쓸 수 없다.

**토큰도 가리지 않는다.** 받은 줄이 통째로 찍히고 인증 헤더 칸에도 들어가며, 요청 기록에도
그대로 남는다. 받자마자 curl 에 붙여 쓰는 일이 많은데 가려 두면 맞게 들어갔는지 볼 수도,
복사해 쓸 수도 없다.

프로젝트 팩이 `PROJECT["login"]` 으로 어디에 무엇을 보낼지 적어 둔다. 앱 본체는
특정 서비스의 로그인 모양을 모른다.

    PROJECT["login"] = {
        "path": "/backend/login",
        "json": {"email": "{id}", "pw": "{secret}"},   # {id}·{secret} 이 입력값으로 바뀐다
        "token_keys": ["token", "data.token"],          # 응답에서 토큰을 찾을 자리
        "header": "Authorization", "prefix": "Bearer ",
        "token_header": "Authorization",                # 토큰이 응답 헤더로 올 때. 빈 값이면 본문만 본다
        "roles": ["user_web"],                          # 이 역할의 대상에만 보인다
    }

역할마다 서버가 다르면 역할 쪽에 적는다. 적은 것만 위 기본값을 덮는다.

    PROJECT["roles"]["admin_web"]["login"] = {
        "path": "/api/admin/login", "json": {"id": "{id}", "pw": "{secret}"},
        "token_keys": ["token"], "token_header": "",    # 이쪽은 본문으로 준다
    }
"""
import base64
import json
import re

from . import core, scope


class LoginFailed(Exception):
    """로그인이 안 됐을 때. 메시지는 사람이 읽을 말로 적는다."""


def config_for(project, role: str = ""):
    """이 대상에 쓸 로그인 설정. 없으면 None.

    **한 프로젝트 안에서 서버가 하나라는 보장이 없다.** 새싹에듀는 사용자 API(EC2 ①)와
    관리자 API(EC2 ②)가 서로 다른 앱이라 경로도, 본문 키도, 토큰이 오는 자리도 다르다
    (11-06 저장소 대조: SesacEdu_Server vs SesacEdu_Admin_Server). 그래서 역할이 자기
    로그인 설정을 들고 있으면 프로젝트 기본값 **위에 덮는다** — 다른 것만 적으면 된다.
    """
    base = getattr(project, "login", None) if project else None
    own = ((project.roles.get(role) or {}).get("login") if (project and role) else None) or {}
    if not base and not own:
        return None
    cfg = {**(base or {}), **own}
    # 역할이 자기 설정을 들고 있으면 그 자체가 '이 역할에 쓴다' 는 뜻이다 — roles 에 또 적지 않는다
    roles = cfg.get("roles") or []
    if not own and roles and role and role not in roles:
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
    """로그인 요청을 한 번 보내고 토큰만 돌려준다. 비밀번호는 DB 에 저장하지 않는다."""
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
                   content_type="application/json")
    if r.status >= 400:
        raise LoginFailed(f"로그인이 거절됐습니다 (응답 {r.status}) — 계정이 맞는지 확인하세요")
    # 토큰을 본문이 아니라 **응답 헤더**로 주는 서버가 있다(새싹에듀 사용자 API /backend/login).
    # 같은 프로젝트의 관리자 API 는 본문으로만 준다. 어느 쪽인지는 팩이 token_header 로 적는다 —
    # 빈 값이면 헤더를 안 본다. 안 적었으면 예전처럼 '넣을 헤더' 이름으로 본다.
    want = cfg.get("token_header", cfg.get("header") or "Authorization")
    if want:
        got = r.header(want)
        if got and got.strip():
            return re.sub(r"^\s*Bearer\s+", "", got.strip())
    return find_token(r.body, cfg.get("token_keys"))


def header_line(cfg: dict, token: str) -> str:
    """대상의 인증 헤더에 넣을 한 줄."""
    return "%s: %s%s" % (cfg.get("header") or "Authorization", cfg.get("prefix") or "", token)


# ── 손으로 넣는 인증 방식(11-20 사용자 요청) ────────────────────────
# 로그인해서 토큰을 받는 길(위)이 전부가 아니다. 토큰을 어디서 이미 받아 뒀거나,
# 브라우저에서 쿠키를 그대로 가져오거나, Basic·API 키를 쓰는 곳이 있다. 모두 결국
# '이름: 값' 한 줄이라 아래에서 그 줄만 만들어 준다 — 저장은 기존 인증 헤더 칸 그대로다.
AUTH_WAYS = [
    {"id": "bearer", "label": "Bearer 토큰", "header": "Authorization",
     "fields": [{"name": "token", "label": "토큰", "ph": "eyJhbGciOi…"}],
     "help": "받아 둔 토큰을 붙여 넣으면 Authorization: Bearer … 로 들어갑니다."},
    {"id": "cookie", "label": "쿠키 주입", "header": "Cookie",
     "fields": [{"name": "cookie", "label": "쿠키", "ph": "JSESSIONID=…; remember=…"}],
     "help": "브라우저 개발자도구의 Cookie 줄을 그대로 붙여 넣습니다."},
    {"id": "basic", "label": "Basic 인증", "header": "Authorization",
     "fields": [{"name": "ident", "label": "아이디", "ph": "test@example.com"},
                {"name": "secret", "label": "비밀번호", "ph": "", "secret": True}],
     "help": "아이디:비밀번호를 base64 로 바꿔 Authorization: Basic … 으로 넣습니다. 값은 그대로 저장됩니다."},
    {"id": "apikey", "label": "API 키", "header": "",
     "fields": [{"name": "name", "label": "헤더 이름", "ph": "X-API-Key"},
                {"name": "value", "label": "키", "ph": ""}],
     "help": "헤더 이름을 직접 적습니다(X-API-Key, X-Auth-Token 등)."},
]
WAY_BY_ID = {w["id"]: w for w in AUTH_WAYS}


def auth_line(way_id: str, form) -> tuple:
    """고른 방식과 입력값 → (헤더 이름, 넣을 한 줄). 값이 비면 ValueError."""
    way = WAY_BY_ID.get(way_id)
    if not way:
        raise ValueError("인증 방식을 고르세요")
    got = {f["name"]: (form.get(f["name"]) or "").strip() for f in way["fields"]}
    missing = [f["label"] for f in way["fields"] if not got[f["name"]]]
    if missing:
        raise ValueError(f"{way['label']}: {', '.join(missing)} 을(를) 적어 주세요")
    if way_id == "bearer":
        return "Authorization", "Authorization: Bearer " + re.sub(r"^\s*Bearer\s+", "", got["token"])
    if way_id == "cookie":
        return "Cookie", "Cookie: " + got["cookie"]
    if way_id == "basic":
        raw = f"{got['ident']}:{got['secret']}".encode("utf-8")
        return "Authorization", "Authorization: Basic " + base64.b64encode(raw).decode()
    name = got["name"]
    if not re.fullmatch(r"[A-Za-z0-9-]+", name):
        raise ValueError("헤더 이름은 영문·숫자·- 만 씁니다")
    return name, f"{name}: {got['value']}"


def replace_line(text: str, name: str, line: str) -> str:
    """같은 이름의 인증 줄만 바꾼다 — 다른 줄(쿠키 등)은 그대로 둔다."""
    keep = [ln for ln in (text or "").splitlines()
            if ln.strip() and ln.split(":", 1)[0].strip().lower() != name.lower()]
    return "\n".join(keep + [line])
