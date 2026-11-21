"""딸깍이를 **MCP 서버**로 연다 — Claude Code 같은 AI 도구가 대시보드를 도구로 쓴다.

왜 만들었나(11-21 사용자 결정). 11월 내내 사람이 화면을 눌러 모듈을 돌리고, 나온 결과를
하나씩 다시 확인했다. 그 확인 작업의 상당 부분은 **같은 질문의 반복**이다 — 이 주소가 진짜
동작인가, 이 판정이 맞나, 다시 보내면 똑같이 나오나. 그 일을 AI 가 직접 하려면 대시보드가
가진 것(대상·지점·결과·모듈)에 손이 닿아야 한다. 그동안은 `curl` 로 화면을 흉내 내서
했는데(CSRF 토큰 받아 폼 흉내), 그건 화면이 바뀌면 깨지는 방식이다.

## 어떻게 붙나

JSON-RPC 2.0 을 `POST /mcp` 한 자리에서 받는다(MCP Streamable HTTP). 붙이는 줄은 연결 탭에
그대로 적혀 있다. **토큰이 있어야 받는다** — 이 대시보드 자체에는 로그인이 없고, 공인 IP 에서
열려 있다. 읽기만 하던 화면과 달리 여기는 **모듈을 돌릴 수 있는 입구**라, 아무나 부르게 두면
그 자체가 취약점이다(우리가 진단하는 바로 그 모양이다).

## 무엇을 내주나

읽기 일곱, 쓰기 둘. 쓰기(모듈 실행·상태 바꾸기)는 연결 탭의 스위치가 꺼져 있으면 거절한다.
스위치는 한 번 켜면 계속 켜져 있다 — 부를 때마다 사람을 부르지는 않는다.

범위는 그대로다. 모듈이 보내는 요청은 `core.fetch` 의 `scope.ensure_in_scope` 를 지나므로
MCP 로 불렀다고 범위 밖 주소에 나가지 않는다. 이 파일은 입구일 뿐 그 검사를 건너뛰지 않는다.
"""
import json
import secrets
from datetime import datetime, timezone

from flask import request

from . import __version__

from .core import KST, now_iso
from .db import STATUSES, get_db

PROTOCOL = "2025-06-18"          # 우리가 말할 줄 아는 MCP 판. 클라이언트가 다른 판을 부르면 그쪽을 따라 적는다
SERVER_NAME = "ttalkkak"
LOG_KEEP = 200                   # 연결 탭에 남겨 두는 호출 기록 수


# ── 설정(쓰기 스위치·토큰) ──────────────────────────────────────

def setting(key, default=""):
    row = get_db().execute("SELECT value FROM app_settings WHERE key = ?", [key]).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    db = get_db()
    db.execute("INSERT INTO app_settings (key, value) VALUES (?, ?) "
               "ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value])
    db.commit()


def token():
    """붙일 때 쓸 토큰. 없으면 한 번 만들어 둔다."""
    t = setting("mcp_token")
    if not t:
        t = secrets.token_urlsafe(24)
        set_setting("mcp_token", t)
    return t


def write_on():
    return setting("mcp_write", "off") == "on"


def authorized():
    """토큰이 맞는지. `Authorization: Bearer …` 또는 `?key=` 둘 다 받는다."""
    sent = (request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            or request.args.get("key", "").strip())
    # 바이트로 견준다 — 글자로 견주면 한글 같은 비 ASCII 가 들어왔을 때 터진다(비교 전에 죽으면
    # 토큰이 틀렸다는 답조차 못 준다)
    return bool(sent) and secrets.compare_digest(sent.encode("utf-8"), token().encode("utf-8"))


# ── 호출 기록 ──────────────────────────────────────────────────

def log(tool, args, ok, summary):
    db = get_db()
    db.execute("INSERT INTO mcp_calls (tool, args, ok, summary, called_at) VALUES (?, ?, ?, ?, ?)",
               [tool, json.dumps(args, ensure_ascii=False)[:500], 1 if ok else 0, summary[:300], now_iso()])
    db.execute("DELETE FROM mcp_calls WHERE id NOT IN (SELECT id FROM mcp_calls ORDER BY id DESC LIMIT ?)", [LOG_KEEP])
    db.commit()


def recent(n=30):
    return get_db().execute("SELECT * FROM mcp_calls ORDER BY id DESC LIMIT ?", [n]).fetchall()


# 붙어 있다고 말할 수 있는 시간. HTTP 라 **연결이 유지되는 것이 아니다** — 요청이 올 때만 붙는다.
# 그래서 '지금 연결됨' 이라고 적으면 거짓말이 된다. 최근에 말을 걸었는지로 적는다.
FRESH_MIN = 15


def _ago(iso):
    """그때로부터 몇 분 지났나 → (분, 사람이 읽는 말). 못 읽는 값이면 (None, '')."""
    try:
        then = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None, ""
    if then.tzinfo is None:
        # 띠 없는 값은 옛 줄이다 — 그때는 sqlite 의 datetime('now')(UTC)로 적었다.
        # 지금은 now_iso()(KST, 띠 붙음)로 적는다. 옛 줄을 KST 로 읽으면 9시간이 어긋난다
        then = then.replace(tzinfo=timezone.utc)
    mins = int((datetime.now(KST) - then).total_seconds() // 60)
    if mins < 1:
        return mins, "방금"
    if mins < 60:
        return mins, f"{mins}분 전"
    if mins < 60 * 24:
        return mins, f"{mins // 60}시간 전"
    return mins, f"{mins // 1440}일 전"


def status():
    """연결 상태 한 덩이 — 화면이 그대로 그린다.

    state 는 셋이다.
        waiting  아직 아무도 말을 건 적이 없다
        live     최근 FRESH_MIN 분 안에 말을 걸었다
        idle     붙었던 적은 있는데 한참 조용하다
    """
    db = get_db()
    last = db.execute("SELECT * FROM mcp_calls ORDER BY id DESC LIMIT 1").fetchone()
    hello = db.execute("SELECT * FROM mcp_calls WHERE tool = 'initialize' ORDER BY id DESC LIMIT 1").fetchone()
    n = db.execute("SELECT COUNT(*) FROM mcp_calls WHERE tool != 'initialize'").fetchone()[0]
    if last is None:
        return {"state": "waiting", "client": "", "when": "", "calls": 0, "last_tool": ""}
    mins, when = _ago(last["called_at"])
    return {"state": "live" if (mins is not None and mins <= FRESH_MIN) else "idle",
            "client": (hello["summary"] if hello else "") or "이름을 안 밝힌 도구",
            "when": when, "calls": n,
            "last_tool": "" if last["tool"] == "initialize" else last["tool"]}


# ── 도구 ───────────────────────────────────────────────────────
# 하나하나가 '사람이 화면에서 하던 일' 과 같다. 설명은 AI 가 읽는 것이라 **무엇을 보고 무엇을
# 판단할 수 있는지** 를 적는다 — 이름만으로는 어느 것을 불러야 할지 모른다.

def _obj(props, required=()):
    return {"type": "object", "properties": props, "required": list(required)}


TOOLS = [
    {"name": "targets", "write": False,
     "description": "점검 대상 목록. 대상마다 id·이름·주소·역할과 모아 둔 지점 수를 준다. "
                    "다른 도구의 target_id 는 여기서 얻는다.",
     "inputSchema": _obj({})},

    {"name": "points", "write": False,
     "description": "한 대상이 모아 둔 지점(요청 자리) 목록. 주소·메서드·파라미터·출처를 준다. "
                    "`run_module` 로 지점 점검 모듈을 돌릴 때 고를 id 가 여기 있다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "대상 id"},
         "contains": {"type": "string", "description": "주소에 이 글자가 든 것만"},
         "params_only": {"type": "boolean", "description": "파라미터가 있는 지점만(기본 false)"},
         "limit": {"type": "integer", "description": "최대 몇 줄(기본 100)"}}, ["target_id"])},

    {"name": "modules", "write": False,
     "description": "이 대상에서 쓸 수 있는 점검 모듈 목록. 모듈마다 무엇을 보는지(단계·취약점 종류·"
                    "설정 칸)를 준다. 단계가 probe 면 지점을 골라야 돌고, check/collect/tool 은 대상만으로 돈다.",
     "inputSchema": _obj({"target_id": {"type": "integer", "description": "대상 id"}}, ["target_id"])},

    {"name": "findings", "write": False,
     "description": "점검 결과 목록. 제목·자리·심각도·처리 상태를 준다. 근거와 다시 보낼 요청은 "
                    "`finding` 으로 한 건씩 본다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "대상 id(비우면 전부)"},
         "status": {"type": "string", "description": "open 미확인 · confirmed 확인됨 · fixed 조치됨 · false_positive 오탐"},
         "severity": {"type": "string", "description": "critical · high · medium · low · info"},
         "contains": {"type": "string", "description": "제목이나 자리에 이 글자가 든 것만"},
         "limit": {"type": "integer", "description": "최대 몇 줄(기본 50)"}})},

    {"name": "finding", "write": False,
     "description": "결과 한 건의 전부 — 근거, 권고, **그대로 다시 보낼 수 있는 요청 한 줄**. "
                    "판정이 맞는지 다시 보려면 이걸 읽고 그 요청을 직접 보내 확인한다.",
     "inputSchema": _obj({"id": {"type": "integer", "description": "결과 id"}}, ["id"])},

    {"name": "coverage", "write": False,
     "description": "점검 범위 — OWASP 2025 와 KISA 21항목이 각각 어떤 상태인지. "
                    "발견(건수 있음) · 점검·없음(모듈이 돌았고 안 나옴) · 모듈 있음·미실행 · 모듈 없음.",
     "inputSchema": _obj({})},

    {"name": "run_status", "write": False,
     "description": "실행 중이거나 막 끝난 모듈의 진행 상태. `run_module` 이 돌려준 run_id 로 본다.",
     "inputSchema": _obj({"run_id": {"type": "integer", "description": "실행 id(비우면 도는 것 전부)"}})},

    {"name": "run_module", "write": True,
     "description": "모듈을 돌린다. 바로 돌아오고 뒤에서 돈다 — 진행은 `run_status` 로 본다. "
                    "단계가 probe 인 모듈은 `points` 에 지점 id 를 적어야 한다. "
                    "보내는 요청은 모두 범위 검사를 지난다(범위 밖 주소로는 나가지 않는다).",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "대상 id"},
         "module_id": {"type": "string", "description": "모듈 id(`modules` 가 준 것)"},
         "points": {"type": "array", "items": {"type": "integer"}, "description": "지점 점검 모듈이면 고를 지점 id 들"},
         "params": {"type": "object", "description": "모듈 설정 칸(`modules` 가 알려 준 이름). 비우면 기본값"}},
         ["target_id", "module_id"])},

    {"name": "cve_candidates", "write": False,
     "description": "점검 결과에 **보인 제품/버전** 과 그에 걸리는 CVE 후보 목록. 기술 지문·서버 정보 "
                    "노출 결과의 근거에서 버전을 뽑고, 팀 CVE 목록과 NVD 에 받아 둔 것을 함께 준다. "
                    "NVD 후보는 버전 범위가 맞는다는 뜻일 뿐이라 늘 '추정' 이다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "대상 id"},
         "ask_nvd": {"type": "boolean", "description": "NVD(services.nvd.nist.gov)에 지금 물어본다. "
                                                        "점검 대상이 아니라 **바깥으로 나가는 요청** 이고 느리다(기본 false)"}},
         ["target_id"])},

    {"name": "make_campaign", "write": True,
     "description": "점검 결과와 CVE 후보로 **침투 시나리오(캠페인) 초안**을 한 벌 짠다. 관찰한 버전과 "
                    "CVE 를 앞단에, 결과를 모듈이 적어 둔 ATT&CK 전술 열에 놓고 전술 순서로 잇는다. "
                    "보고서에 그대로 옮길 줄거리도 같이 돌려준다. 단계 사이에 무엇을 넘겼는지는 사람이 적는다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "대상 id"},
         "name": {"type": "string", "description": "캠페인 이름(비우면 '<대상> 침투 시나리오')"},
         "goal": {"type": "string", "description": "이 시나리오의 목표 한 줄"},
         "statuses": {"type": "array", "items": {"type": "string"},
                      "description": "어떤 처리 상태의 결과를 넣을지(기본 confirmed 만). open 을 넣으면 미확인도"},
         "severity": {"type": "array", "items": {"type": "string"},
                      "description": "넣을 심각도(critical·high·medium·low). 비우면 info 만 뺀다. "
                                     "확인됨이 많은 대상은 critical·high 로 좁히는 게 읽기 좋다"},
         "top": {"type": "integer",
                 "description": "보드에 올릴 가짓수 상한(기본 20). 같은 제목은 한 노드로 묶고 심한 것부터 올린다"}},
         ["target_id"])},

    {"name": "set_status", "write": True,
     "description": "결과의 처리 상태를 바꾼다. 확인했으면 confirmed, 틀렸으면 false_positive. "
                    "**왜 그렇게 봤는지 note 에 남긴다** — 근거 없는 판정은 다음 사람이 다시 확인해야 한다.",
     "inputSchema": _obj({
         "id": {"type": "integer", "description": "결과 id"},
         "status": {"type": "string", "description": "open · confirmed · fixed · false_positive"},
         "note": {"type": "string", "description": "그렇게 본 까닭 한 줄(근거 끝에 붙는다)"}},
         ["id", "status"])},
]

BY_NAME = {t["name"]: t for t in TOOLS}


def listed():
    """MCP 가 보는 모양 — 우리끼리 쓰는 `write` 는 빼고 준다."""
    return [{k: v for k, v in t.items() if k != "write"} for t in TOOLS]


# ── JSON-RPC ───────────────────────────────────────────────────

def _ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _text(s):
    return {"content": [{"type": "text", "text": s}]}


def _fail(s):
    return {"content": [{"type": "text", "text": s}], "isError": True}


def handle(payload, call_tool):
    """JSON-RPC 한 건을 처리한다 → 돌려줄 dict, 알림이면 None.

    `call_tool(name, args) -> 글자` 는 라우트가 넘겨준다. 도구의 실제 일은 routes 쪽에 있다 —
    DB·모듈·실행은 거기 손이 닿는 것들이고, 이 파일은 말을 주고받는 자리만 맡는다.
    """
    if isinstance(payload, list):                       # 묶어 보낸 요청
        out = [handle(p, call_tool) for p in payload]
        return [r for r in out if r is not None] or None

    rid = payload.get("id")
    method = payload.get("method", "")
    params = payload.get("params") or {}

    if method == "initialize":
        asked = (params.get("protocolVersion") or "").strip()
        who = params.get("clientInfo") or {}
        # 누가 붙었는지는 이 인사에만 들어 있다. 화면의 '붙어 있음' 은 이 줄을 보고 적는다
        log("initialize", {"client": who.get("name", ""), "version": who.get("version", "")}, True,
            (who.get("name") or "이름을 안 밝힌 도구") + (f' {who["version"]}' if who.get("version") else ""))
        return _ok(rid, {
            "protocolVersion": asked or PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
            "instructions": "새싹에듀 모의해킹 점검 대시보드입니다. 대상은 팀이 가진 실습 서버뿐이고, "
                            "모듈이 보내는 요청은 모두 범위 검사를 지납니다. 결과를 확인했으면 "
                            "`set_status` 로 까닭과 함께 남겨 주세요.",
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _ok(rid, {})
    if method == "tools/list":
        return _ok(rid, {"tools": listed()})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        tool = BY_NAME.get(name)
        if not tool:
            return _ok(rid, _fail(f"그런 도구가 없습니다: {name}"))
        if tool["write"] and not write_on():
            return _ok(rid, _fail(
                "쓰기 도구가 꺼져 있습니다. 대시보드의 **연결** 탭에서 '쓰기 도구 켜기' 를 켜면 됩니다. "
                "읽기 도구(targets·points·findings·finding·coverage·modules·run_status)는 그대로 씁니다."))
        try:
            out = call_tool(name, args)
            log(name, args, True, out.splitlines()[0] if out else "")
            return _ok(rid, _text(out))
        except Exception as e:                           # noqa: BLE001 — 도구 하나가 죽어도 연결은 산다
            log(name, args, False, f"{type(e).__name__}: {e}")
            return _ok(rid, _fail(f"{name} 이 실패했습니다: {e}"))
    return _err(rid, -32601, f"모르는 메서드입니다: {method}")


def connect_command(base_url):
    """연결 탭에 그대로 적어 둘 한 줄."""
    return (f'claude mcp add ttalkkak --transport http {base_url.rstrip("/")}/mcp '
            f'--header "Authorization: Bearer {token()}"')
