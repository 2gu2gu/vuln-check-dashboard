"""서버 안에서 받은 명령 출력을 붙여 넣으면 결과로 바꿔 준다.

대시보드는 HTTP 로만 말한다 — SSH 로 들어가 명령을 대신 실행하지는 않는다.
(그렇게 만들면 범위 검사가 닿지 않는 원격 실행 도구가 된다.)
그래서 서버 쪽 점검은 사람이 서버에서 직접 받아 온 출력을 여기에 붙여 넣는 방식으로 받는다.

받는 것
  sudo --version      설치된 sudo 버전
  ss -tlnp            듣고 있는 포트 (netstat -tlnp 도 됨)
붙여 넣은 글은 그대로 두고, 버전·포트 줄만 읽는다. 요청은 한 번도 보내지 않는다.
"""
import re

from dashboard.core import Finding, ToolResult

META = {
    "id": "host_report",
    "name": "서버 명령 출력 읽기",
    "category": "서버 설정",
    "kind": "passive",
    "stage": "tool",
    "severity": "medium",
    "attack": [
        {"tactic": "TA0007", "technique": "T1082", "name": "System Information Discovery"},
        {"tactic": "TA0004", "technique": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "description": "서버에서 받은 sudo --version · ss -tlnp 출력을 붙여 넣으면 버전과 열린 포트를 정리하고 기준에 못 미치는 것을 표시합니다. 요청은 보내지 않습니다.",
    "needs": [
        {"kind": "account", "name": "서버 접속",
         "why": "대시보드는 SSH 명령을 대신 실행하지 않습니다 — 범위 검사가 닿지 않는 원격 실행 도구가 되기 때문입니다",
         "how": "서버에 직접 들어가 sudo --version 과 ss -tlnp 를 돌리고 그 출력을 붙여 넣습니다"},
    ],
    "params": [
        {"name": "output", "label": "명령 출력 붙여 넣기", "type": "textarea", "default": "",
         "placeholder": "$ sudo --version\nSudo version 1.9.15p5\n\n$ ss -tlnp\nLISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))"},
        {"name": "fixed", "label": "안전한 최소 버전 (이름 버전)", "type": "textarea",
         "default": "sudo 1.9.17",
         "help": "한 줄에 하나. 붙여 넣은 버전이 이보다 낮으면 표시합니다. 기준은 배포판 보안 공지를 보고 팀이 정합니다."},
        {"name": "public_ports", "label": "밖에 열려도 되는 포트", "default": "22,80,443",
         "help": "0.0.0.0 으로 열려 있는데 이 목록에 없으면 표시합니다."},
    ],
}

VERSION = re.compile(r"(?i)\b(sudo|openssh|nginx|apache|tomcat|openssl)\b[^\d\n]{0,20}(\d+\.\d+(?:\.\d+)?)")
LISTEN = re.compile(r"(?m)^.*?\bLISTEN\b.*?(?:^|\s)(\S*?[\d.:*\[\]]+):(\d+)\s")
PROCESS = re.compile(r'users:\(\("([^"]+)"')


def _parts(version):
    return [int(n) for n in re.findall(r"\d+", version)]


def run(target, params):
    text = params.get("output", "")
    if not text.strip():
        raise ValueError("서버에서 받은 명령 출력을 붙여 넣어 주세요")

    fixed = {}
    for line in params.get("fixed", "").splitlines():
        bits = line.split()
        if len(bits) >= 2:
            fixed[bits[0].lower()] = bits[1]
    public = {p.strip() for p in params.get("public_ports", "").split(",") if p.strip()}

    rows, findings = [], []

    # 버전
    seen = set()
    for name, version in VERSION.findall(text):
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        want = fixed.get(key)
        old = bool(want) and _parts(version) < _parts(want)
        rows.append(["버전", name.lower(), version, f"기준 {want} 보다 낮음" if old else (f"기준 {want} 이상" if want else "기준 없음")])
        if old:
            findings.append(Finding(
                title=f"{key} {version} — 정해 둔 기준보다 낮음",
                severity="medium", location=f"{target.name} (서버)",
                evidence=f"붙여 넣은 출력에서 읽음: {name} {version}\n팀이 정한 기준: {want}",
                recommendation=f"{key} 를 {want} 이상으로 올리거나, 실습을 위해 일부러 낮춰 둔 것이면 "
                               "시나리오 문서에 그 사실과 되돌릴 방법을 적어 둡니다.",
                technique="T1068"))

    # 듣고 있는 포트
    procs = PROCESS.findall(text)
    for i, (addr, port) in enumerate(LISTEN.findall(text)):
        outside = addr in ("0.0.0.0", "*", "[::]", "::")
        proc = procs[i] if i < len(procs) else ""
        note = "밖으로 열림" if outside and port not in public else ("밖으로 열림(허용)" if outside else "안에서만")
        rows.append(["포트", proc or "-", f"{addr}:{port}", note])
        if outside and port not in public:
            findings.append(Finding(
                title=f"{port} 포트가 밖으로 열려 있음" + (f" ({proc})" if proc else ""),
                severity="medium", location=f"{target.name} (서버 {addr}:{port})",
                evidence=f"붙여 넣은 출력에서 읽음: {addr}:{port}" + (f" — {proc}" if proc else ""),
                recommendation=f"{port} 가 밖에서 닿아야 하는지 확인하고, 아니면 127.0.0.1 로만 듣게 하거나 "
                               "보안 그룹에서 막습니다.",
                technique="T1082"))

    if not rows:
        raise ValueError("읽을 수 있는 줄이 없습니다. sudo --version 이나 ss -tlnp 출력을 넣어 주세요")

    return ToolResult(
        summary=f"{len(rows)}줄 읽음 · 표시할 것 {len(findings)}건",
        columns=["종류", "이름", "값", "판단"], rows=rows, findings=findings,
        note="요청을 보내지 않습니다. 붙여 넣은 내용만 읽습니다 — 비밀번호·키가 섞인 출력은 넣지 마세요.")
