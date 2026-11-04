"""서버 디렉터리 구조를 글자 트리로 그린다.

경로 조작으로 알아낸 것을 사람이 읽을 수 있게 늘어놓는 일만 한다.
요청을 보내지도, 판정하지도 않는다 — 그린 것을 어떻게 읽어야 하는지만 조심한다.

404 는 그리지 않는다. 404 는 '없음' 이 아니라 **stat 실패**라서,
없는 것인지 상위 경로에 탐색 권한이 없는 것인지 응답으로는 가릴 수 없다.
'못 들어감' 도 파일인지 디렉터리인지 가리지 못한 상태를 그대로 적은 것이다.

전에는 '칼리 fsmap 결과 가져오기' 모듈 안에 있었다. 그 모듈을 없애면서
(대시보드가 직접 퍼징해 같은 지도를 그린다) 그리는 일만 여기로 남겼다.
"""

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
