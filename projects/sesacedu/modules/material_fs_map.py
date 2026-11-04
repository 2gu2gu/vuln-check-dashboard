"""칼리 fsmap 결과 가져오기 — 서버 파일시스템 구조를 지도로 본다.

fsmap 은 자료 다운로드 경로 조작으로 서버 디렉터리 구조를 그리는 칼리 도구다
(26차시 실무 프로젝트/08_모의해킹/file_inclution/fsmap).

    python3 run.py walk --export all
    → out/fsmap.json 을 여기에 붙여 넣는다

이 모듈은 **요청을 보내지 않는다.** 바깥 도구를 대시보드가 대신 실행하면 범위 검사가
그 도구가 보내는 것까지 닿지 못한다 — modules/import_tool_output.py 와 같은 판단이다.
칼리에서 사람이 돌리고, 결과만 여기로 옮긴다.

왜 응답 코드로 구조를 알 수 있나
    404  stat 실패 — **없음, 또는 상위 경로에 탐색 권한이 없음**
    500  있는데 파일로 못 보냄 — 디렉터리이거나 읽기 권한이 없다
    200  파일이고 읽혔다
  디렉터리 목록을 주는 취약점이 아니라서, 코드 자체를 오라클로 쓴다.

두 가지를 단정하지 않는다.
  · 404 를 '없음'으로 읽지 않는다. 리눅스에서 /a/b 를 stat 하려면 /a 에 실행(탐색)
    권한이 필요하고, 없으면 EACCES 로 실패해 404 가 된다. /root 가 0700 이면
    /root/.bashrc 는 **있는데도 404** 다. 그래서 404 경로는 표에 올리지 않는다.
  · 500 을 '읽기 권한 없는 파일'로 읽지 않는다. 못 읽는 파일(ENOTDIR)과
    못 들어가는 디렉터리(EACCES)가 '<경로>/..' 에 **같은 응답**을 준다.
    fsmap 은 이 경우를 kind="opaque" 로 넘기고, 여기서도 그대로 '못 들어감'으로 적는다.
"""
import json

from dashboard.core import Finding, ToolResult

META = {
    "id": "sesacedu_material_fs_map",
    "name": "칼리 fsmap 결과 가져오기 (파일시스템 지도)",
    "category": "경로 조작",
    # 노션 '웹 서비스 취약점 목록' 의 취약점 유형 — 경로 조작으로 그린 파일시스템 지도를 읽어 들이는 것
    "vuln": "FILE",
    "kind": "passive",
    "roles": ["user_web", "practice"],
    "stage": "tool",
    "severity": "high",
    "attack": [
        {"tactic": "TA0007", "technique": "T1083", "name": "File and Directory Discovery"},
        {"tactic": "TA0009", "technique": "T1005", "name": "Data from Local System"},
    ],
    "description": "칼리 fsmap 의 out/fsmap.json 을 붙여 넣으면 서버 디렉터리 구조를 "
                   "트리로 그리고, 읽힌 민감 파일을 결과로 올립니다. 요청은 보내지 않습니다.",
    "needs": [
        {"kind": "tool", "name": "fsmap",
         "why": "이 모듈은 요청을 보내지 않습니다 — 칼리에서 사람이 돌린 결과를 읽기만 합니다",
         "how": "08_모의해킹/file_inclution/fsmap 에서 python3 run.py walk --export all 을 돌려 out/fsmap.json 을 만든 뒤 붙여 넣습니다"},
    ],
    "params": [
        {"name": "fsmap", "label": "fsmap.json 붙여 넣기", "type": "textarea", "default": "",
         "placeholder": '{"tool":"fsmap","nodes":[{"path":"/etc/passwd","class":"readable",'
                        '"status":200,"size":1990,"is_dir":false,"severity":"medium"}]}',
         "help": "칼리에서 `python3 run.py walk --export all` 을 돌리면 out/fsmap.json 이 생깁니다."},
        {"name": "min_severity", "label": "결과로 올릴 최소 민감도", "type": "select",
         "default": "high",
         "options": [{"value": "critical", "label": "치명만"},
                     {"value": "high", "label": "높음 이상"},
                     {"value": "medium", "label": "보통 이상"},
                     {"value": "info", "label": "전부"}],
         "help": "읽힌 파일 중 이 등급 이상만 결과 탭에 올립니다. 트리는 전부 보여 줍니다."},
    ],
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": "  ", "info": "  "}
MAX_NODES = 4000
MAX_ROWS = 200

DIR = "dir"        # 들어갈 수 있는 디렉터리
OPAQUE = "opaque"  # 있지만 못 들어감 — 못 읽는 파일인지 못 들어가는 디렉터리인지 가릴 수 없다
KIND_LABEL = {DIR: "디렉터리", OPAQUE: "못 들어감"}


def _kind(node):
    """fsmap 의 kind. 예전 형식(is_dir)만 있으면 True 일 때만 디렉터리로 본다.

    예전 형식의 is_dir=False 는 '파일'이라는 **틀린 단정**이었으므로 믿지 않는다.
    """
    kind = node.get("kind")
    if kind in (DIR, OPAQUE):
        return kind
    return DIR if node.get("is_dir") is True else None


def _size(n):
    if n >= 1048576:
        return "%.1fMB" % (n / 1048576.0)
    if n >= 1024:
        return "%.1fKB" % (n / 1024.0)
    return "%dB" % n


def _tree(nodes):
    """경로 목록을 트리 글자로. nodes = [dict, ...]"""
    root = {}
    for node in sorted(nodes, key=lambda n: n["path"]):
        cur = root
        parts = [p for p in node["path"].strip("/").split("/") if p]
        for i, part in enumerate(parts):
            entry = cur.setdefault(part, {"node": None, "children": {}})
            if i == len(parts) - 1:
                entry["node"] = node
            cur = entry["children"]

    lines = ["   /"]

    def walk(level, prefix):
        names = sorted(level)
        for idx, name in enumerate(names):
            last = idx == len(names) - 1
            entry, node, kids = level[name], level[name]["node"], level[name]["children"]
            branch = "└── " if last else "├── "
            if node is None:
                label, tail, mark = name + "/", "  (중간 경로)", "  "
            else:
                mark = SEV_MARK.get(node.get("severity", "info"), "  ")
                kind = _kind(node)
                if kind == DIR or (node.get("class") == "exists" and kids):
                    label, tail = name + "/", "  [%s]" % node.get("status")
                    if node.get("blocked"):
                        tail += "  (안쪽 전부 404 — 사전 미포함/비었음/탐색 권한 없음)"
                elif node.get("class") == "readable":
                    label, tail = name, "  [200 · %s]" % _size(node.get("size", 0))
                elif kind == OPAQUE:
                    label = name
                    tail = "  [%s · 못 들어감: 파일/디렉터리 구분 불가]" % node.get("status")
                else:
                    label, tail = name, "  [%s · 종류 미판별]" % node.get("status")
                if node.get("note"):
                    tail += "  — " + node["note"]
            lines.append("%s %s%s%s%s" % (mark, prefix, branch, label, tail))
            if kids:
                walk(kids, prefix + ("    " if last else "│   "))

    walk(root, "")
    lines += ["", "   범례  !! 치명  ! 높음  ~ 보통   |   [200]=읽힘  "
                  "[500]=있으나 파일로 못 보냄  이름 끝 / = 들어갈 수 있는 디렉터리",
              "         404 는 그리지 않는다 — '없음'이 아니라 "
              "'없음 또는 탐색 권한 없음'이라 단정할 수 없다"]
    return "\n".join(lines)


def _sent_text(blob):
    """칼리 fsmap 이 보낸 요청 수.

    0 을 '0건' 이라고 쓰면 안 된다 — **센 적이 없다**는 뜻일 수 있다. fsmap 을 이어서
    돌리면 Prober 가 새로 만들어져 카운터가 0 부터 시작하는데, 예전 내보내기는 그
    0 을 그대로 실었다. 94개를 찾아 놓고 '보낸 요청 0건' 으로 보이던 원인이다.
    """
    st = blob.get("stats") or {}
    sent = st.get("요청")
    if not sent:
        n404 = blob.get("unstat_count")
        hint = (" — 404 만 %d건이니 실제로는 그보다 많이 보냈습니다" % n404) if n404 else ""
        return "기록 없음%s" % hint
    spans = st.get("세션") or len(st.get("구간") or []) or 1
    return "%d건%s" % (sent, " (%d회에 나눠 실행)" % spans if spans > 1 else "")


def run(target, params):
    text = (params.get("fsmap") or "").strip()
    if not text:
        raise ValueError("칼리 fsmap 의 out/fsmap.json 내용을 붙여 넣어 주세요")
    try:
        blob = json.loads(text)
    except ValueError as exc:
        raise ValueError("JSON 으로 읽을 수 없습니다: %s" % exc)
    if not isinstance(blob, dict) or not isinstance(blob.get("nodes"), list):
        raise ValueError("fsmap 결과가 아닙니다. 'nodes' 가 있는 json 이어야 합니다 "
                         "(`run.py export --format json` 으로 만든 파일)")

    nodes = [n for n in blob["nodes"] if isinstance(n, dict) and n.get("path")]
    if not nodes:
        raise ValueError("nodes 가 비어 있습니다. 칼리에서 먼저 `seeds` 나 `walk` 를 돌리세요")
    if len(nodes) > MAX_NODES:
        raise ValueError("한 번에 %d개까지 읽습니다 (지금 %d개)" % (MAX_NODES, len(nodes)))

    meta = blob.get("meta") or {}
    readable = [n for n in nodes if n.get("class") == "readable"]
    opaque = [n for n in nodes if _kind(n) == OPAQUE]
    dirs = [n for n in nodes if _kind(n) == DIR]
    blocked = [n for n in nodes if n.get("blocked")]

    limit = SEV_ORDER.get(params.get("min_severity", "high"), 1)
    picked = sorted((n for n in readable
                     if SEV_ORDER.get(n.get("severity", "info"), 4) <= limit),
                    key=lambda n: (SEV_ORDER.get(n.get("severity", "info"), 4), n["path"]))

    rows, drills = [], []
    for n in sorted(nodes, key=lambda x: (SEV_ORDER.get(x.get("severity", "info"), 4), x["path"]))[:MAX_ROWS]:
        kind = KIND_LABEL.get(_kind(n), "미판별")
        if n.get("class") == "readable":
            kind = "파일"
        state = {"readable": "읽힘", "exists": "있음"}.get(n.get("class"), n.get("class", "?"))
        if n.get("blocked"):
            state = "있음 · 안쪽 전부 404"
        rows.append([n["path"], n.get("status", "—"),
                     _size(n.get("size", 0)) if n.get("class") == "readable" else "—",
                     kind, n.get("severity", "info"), state])
        # 읽힌 파일은 경로 조작 도구로 바로 내용 보기로 이어 준다
        drills.append({"내용 보기": {"paths": n["path"].lstrip("/")}}
                      if n.get("class") == "readable" else None)

    findings = []
    if readable:
        findings.append(Finding(
            title="경로 조작으로 서버 파일시스템 구조 확인 (읽힌 파일 %d개)" % len(readable),
            severity="high",
            location=meta.get("base_url", target.url) + (meta.get("endpoint") or ""),
            evidence=("인코딩 %s · 올라간 단계 %s · 칼리 fsmap 이 보낸 요청 %s · 실행 %s\n"
                      "(딸깍이는 이 모듈에서 요청을 보내지 않습니다 — 칼리 결과를 읽기만 합니다)\n"
                      "존재 %d · 읽힘 %d · 디렉터리 %d · 못 들어감 %d · 막힌 가지 %d\n\n"
                      "읽힌 파일(앞 20개)\n%s\n\n"
                      "해석 주의: 404 였던 경로는 '없다'고 단정하지 않는다 — "
                      "상위 경로에 탐색 권한이 없어도 404 가 온다."
                      % (meta.get("scheme", "?"), meta.get("depth", "?"),
                         _sent_text(blob), meta.get("window") or "기록 없음",
                         len(nodes), len(readable), len(dirs), len(opaque), len(blocked),
                         "\n".join("  %s (%s)" % (n["path"], _size(n.get("size", 0)))
                                   for n in readable[:20]))),
            recommendation=("경로를 정규화(realpath)한 뒤 저장 폴더 안인지 검사하고, URL 디코딩은 "
                            "먼저 한 번만 합니다. 더 나은 방법은 파일 이름을 받지 않고 자료 번호로만 "
                            "찾는 것입니다. 구조가 드러나면 다음 공격의 표적이 좁혀지므로, "
                            "읽힌 설정 파일에 든 자격증명은 전부 교체해야 합니다.")))
    for n in picked:
        findings.append(Finding(
            title="민감 파일 노출: %s" % n["path"],
            severity=n.get("severity", "high"),
            location=meta.get("base_url", target.url),
            evidence="%s · %s · 응답 %s\n%s" % (n["path"], _size(n.get("size", 0)),
                                              n.get("status"), n.get("note", "")),
            recommendation="경로 조작을 먼저 막고, 이 파일에 자격증명이 들어 있으면 교체합니다."))

    note = ("요청을 보내지 않았습니다 — 칼리에서 받은 결과를 읽기만 했습니다. "
            "표는 민감도 순 앞 %d개이고, 파일 내용은 fsmap 결과에 들어 있지 않습니다"
            "(경로·크기·응답 코드만). 내용을 보려면 행의 '내용 보기' 로 "
            "'자료 다운로드 경로 조작' 도구로 넘어갑니다. "
            "**없는 경로는 여기 없습니다** — 404 는 '없음'이 아니라 '없음 또는 상위 경로에 "
            "탐색 권한 없음'이라서, 404 였던 경로를 '없다'고 적을 수 없습니다. "
            "'못 들어감' 은 읽기 권한 없는 파일인지 탐색 권한 없는 디렉터리인지 "
            "응답으로 가릴 수 없는 경우입니다." % min(len(nodes), MAX_ROWS))
    if blob.get("stopped"):
        note += " · 칼리 쪽이 중간에 멈췄습니다: %s (지도가 완전하지 않습니다)" % blob["stopped"]

    return ToolResult(
        summary="존재 %d · 읽힘 %d · 디렉터리 %d · 못 들어감 %d · 막힌 가지 %d"
                % (len(nodes), len(readable), len(dirs), len(opaque), len(blocked)),
        columns=["경로", "응답", "크기", "종류", "민감도", "상태"],
        rows=rows, drills=drills,
        text=_tree(nodes),
        findings=findings,
        note=note)
