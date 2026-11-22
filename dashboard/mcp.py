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
     "description": "스캔 대상(타깃) 목록을 조회합니다. 각 항목은 id, 이름, URL, 역할, 수집된 엔드포인트 수를 포함합니다. 다른 도구의 `target_id` "
                    "입력값은 이 도구에서 얻습니다.",
     "inputSchema": _obj({})},

    {"name": "points", "write": False,
     "description": "한 타깃에서 수집된 엔드포인트 목록을 조회합니다. 각 항목은 URL, 메서드, 파라미터와 파라미터 위치(query·json·form·path), 수집 "
                    "출처를 포함합니다. `run_module` 로 엔드포인트 단위 모듈(stage=probe)을 실행할 때 지정할 id 가 여기에 있습니다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "타깃 id"},
         "contains": {"type": "string", "description": "URL 부분 일치 필터"},
         "params_only": {"type": "boolean", "description": "파라미터가 있는 엔드포인트만 반환(기본 false)"},
         "limit": {"type": "integer", "description": "최대 반환 건수(기본 100)"}}, ["target_id"])},

    {"name": "modules", "write": False,
     "description": "해당 타깃에서 실행 가능한 진단 모듈 목록을 조회합니다. 각 모듈의 실행 단위(stage), 취약점 분류, 심각도, 설정 가능한 파라미터를 반환합니다. "
                    "stage=probe 는 엔드포인트 지정이 필요하고, check·collect·tool 은 타깃만으로 실행됩니다.",
     "inputSchema": _obj({"target_id": {"type": "integer", "description": "타깃 id"}}, ["target_id"])},

    {"name": "findings", "write": False,
     "description": "진단 결과(취약점) 목록을 조회합니다. 제목, 위치, 심각도, 처리 상태를 반환하며 타깃·상태·심각도·키워드로 필터링합니다. 상세 증적과 재현 요청은 "
                    "`finding` 으로 건별 조회합니다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "타깃 id(생략 시 전체)"},
         "status": {"type": "string", "description": "open 미확인 · confirmed 확인됨 · fixed 조치됨 · false_positive 오탐"},
         "severity": {"type": "string", "description": "critical · high · medium · low · info"},
         "contains": {"type": "string", "description": "제목·위치 부분 일치 필터"},
         "limit": {"type": "integer", "description": "최대 반환 건수(기본 50)"}})},

    {"name": "finding", "write": False,
     "description": "진단 결과 한 건의 상세를 조회합니다. 판정 근거(요청·응답 요약), 조치 권고, 그대로 재전송 가능한 **재현 요청 원문**을 반환합니다. 판정을 검증할 "
                    "때는 이 요청을 직접 보내 응답을 확인하십시오.",
     "inputSchema": _obj({"id": {"type": "integer", "description": "진단 결과 id"}}, ["id"])},

    {"name": "coverage", "write": False,
     "description": "진단 커버리지를 조회합니다. OWASP Top 10 2025 와 KISA 주요정보통신기반시설 웹 21항목 각각에 대해 발견(건수 있음), 점검·없음(모듈 "
                    "실행 후 미검출), 모듈 있음·미실행, 모듈 없음 중 하나로 상태를 반환합니다.",
     "inputSchema": _obj({})},

    {"name": "run_status", "write": False,
     "description": "모듈 실행의 진행 상태를 조회합니다. `run_module` 이 반환한 run_id 로 지정하며, 상태·전송 요청 수·소요 시간·종료 메시지를 반환합니다.",
     "inputSchema": _obj({"run_id": {"type": "integer", "description": "실행 id(생략 시 진행 중인 실행 전체)"}})},

    {"name": "run_module", "write": True,
     "description": "진단 모듈을 실행합니다. **비동기**로 동작하여 run_id 를 즉시 반환하고, 진행은 `run_status` 로 조회합니다. stage=probe "
                    "모듈은 `points` 에 엔드포인트 id 를 지정해야 합니다. 전송되는 모든 요청은 스코프 검증을 거치며, 허용 범위 밖 호스트로는 나가지 않습니다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "타깃 id"},
         "module_id": {"type": "string", "description": "모듈 id(`modules` 응답의 값)"},
         "points": {"type": "array", "items": {"type": "integer"}, "description": "stage=probe 모듈에 지정할 엔드포인트 id 배열"},
         "params": {"type": "object", "description": "모듈 파라미터(`modules` 가 제시한 이름). 생략 시 기본값"}},
         ["target_id", "module_id"])},

    {"name": "cve_candidates", "write": False,
     "description": "진단 결과에서 **식별된 제품·버전**과 해당 버전에 영향을 주는 CVE 후보를 조회합니다. 버전은 배너·기술 지문·정보 노출 결과의 증적과 노출된 파일 "
                    "경로에서 추출하며, 팀이 검증한 CVE 목록과 NVD 조회 결과를 함께 반환합니다. NVD 후보는 버전 범위 일치만을 의미하므로 상태는 항상 '추정' "
                    "입니다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "타깃 id"},
         "ask_nvd": {"type": "boolean", "description": "NVD(services.nvd.nist.gov)에 실시간 조회합니다. "
                                                        "진단 대상이 아닌 **외부로 나가는 요청**이며 응답이 느립니다(기본 false)"}},
         ["target_id"])},

    {"name": "make_campaign", "write": True,
     "description": "진단 결과를 바탕으로 공격 시나리오(캠페인) 초안을 생성합니다. 체인은 **식별된 제품·버전 → 해당 버전에 영향을 주는 CVE → 그 전술에 속한 진단 "
                    "결과 → 달성 가능한 목표** 순으로 구성되며, 각 노드는 ATT&CK 전술에 배치됩니다. 팀이 검증한 CVE 는 등록된 전술·상태·근거 문서를 그대로 "
                    "사용하고, 진단 결과는 해당 결과의 ATT&CK 기법이 속한 전술에 배치합니다. 근거가 있는 연결만 생성하며(버전 일치, 동일 제품, 목표 달성 가능), "
                    "보고서용 요약 텍스트를 함께 반환합니다. 단계 간 획득물(토큰·셸 등)은 분석가가 보드에서 직접 연결합니다.",
     "inputSchema": _obj({
         "target_id": {"type": "integer", "description": "타깃 id"},
         "name": {"type": "string", "description": "캠페인 이름(생략 시 '<타깃> 침투 시나리오')"},
         "goal": {"type": "string", "description": "시나리오 목표 한 줄"},
         "statuses": {"type": "array", "items": {"type": "string"},
                      "description": "포함할 처리 상태(기본 confirmed). open 을 넣으면 미확인 결과도 포함"},
         "severity": {"type": "array", "items": {"type": "string"},
                      "description": "포함할 심각도(critical·high·medium·low). 생략 시 info 만 제외. "
                                     "결과가 많은 타깃은 critical·high 로 좁히는 편이 읽기 좋습니다"},
         "top": {"type": "integer",
                 "description": "보드에 배치할 최대 노드 수(기본 20). 동일 제목은 한 노드로 묶고 심각도 순으로 선택합니다"}},
         ["target_id"])},

    {"name": "set_status", "write": True,
     "description": "진단 결과의 처리 상태를 변경합니다(open·confirmed·fixed·false_positive). 검증한 근거를 `note` 에 남기십시오 — 근거 "
                    "없는 판정은 재검증 대상이 됩니다.",
     "inputSchema": _obj({
         "id": {"type": "integer", "description": "진단 결과 id"},
         "status": {"type": "string", "description": "변경할 상태: open · confirmed · fixed · false_positive"},
         "note": {"type": "string", "description": "판정 근거 한 줄(증적 끝에 추가됩니다)"}},
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
