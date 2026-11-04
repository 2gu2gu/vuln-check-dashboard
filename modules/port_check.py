"""밖에서 어떤 포트가 열려 있는지 확인한다 — 정해 둔 포트에 TCP 연결만 해 본다.

`ss -tlnp`(서버 명령 출력 읽기)는 서버가 무엇을 듣고 있는지 알려 주지만,
방화벽·보안 그룹을 지나 **밖에서 실제로 닿는지**는 알려 주지 않는다. 그 차이를 보는 모듈이다.

이 모듈만 HTTP 가 아니라 TCP 로 나간다. 그래서 검사도 따로 받는다
  · 역할의 포트 제한은 쓰지 않는다 — 모르는 포트를 찾는 일이라 쓸 수가 없다
  · 대신 호스트가 프로젝트 범위 안인지 반드시 본다
  · 적어 둔 포트에만, 한 번에 조금씩. 포트를 통째로 훑는 용도가 아니다
연결 요청만 보내고 바로 끊는다. 데이터를 주고받지 않는다.
"""
from dashboard.core import Finding, ToolResult, tcp_check
from dashboard.scope import host_port_of

META = {
    "id": "port_check",
    "name": "열린 포트 확인",
    "category": "서버 설정",
    "kind": "active",
    "stage": "tool",
    "severity": "medium",
    "transport": "tcp",        # HTTP 가 아니라 TCP 로 나간다는 표시(기록용)
    "attack": [{"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Scanning IP Blocks"}],
    "description": "적어 둔 포트에 TCP 연결만 해 보고 밖에서 닿는지 확인합니다. 대상 호스트에만, 적어 둔 포트에만 보냅니다.",
    "params": [
        {"name": "ports", "need": "required", "label": "확인할 포트 (쉼표)", "default": "22,80,443,1521,3000,3389,8080,8443",
         "help": "포트를 통째로 훑는 용도가 아닙니다. 궁금한 포트만 적으세요(한 번에 30개까지)."},
        {"name": "expected", "need": "optional", "label": "열려 있어도 되는 포트", "default": "443",
         "help": "여기에 없는데 열려 있으면 결과로 남깁니다."},
        {"name": "timeout", "need": "optional", "label": "기다릴 시간(초)", "type": "int", "default": "2"},
    ],
}

MAX_PORTS = 30
LABEL = {"open": "열림", "closed": "닫힘", "filtered": "응답 없음"}


def _ports(text, label):
    out = []
    for bit in (text or "").replace(" ", "").split(","):
        if not bit:
            continue
        if not bit.isdigit() or not 1 <= int(bit) <= 65535:
            raise ValueError(f"{label} 에 포트가 아닌 값이 있습니다: {bit}")
        out.append(int(bit))
    return out


def run(target, params):
    host, _ = host_port_of(target.url)
    ports = _ports(params.get("ports"), "확인할 포트")
    expected = set(_ports(params.get("expected"), "열려 있어도 되는 포트"))
    timeout = float(params.get("timeout") or 2)
    if not ports:
        raise ValueError("확인할 포트를 적어 주세요")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"한 번에 {MAX_PORTS}개까지 확인합니다 (지금 {len(ports)}개)")

    rows, open_unexpected = [], []
    for port in sorted(set(ports)):
        result = tcp_check(host, port, timeout)
        note = ""
        if result == "open":
            note = "예상대로" if port in expected else "예상 밖"
            if port not in expected:
                open_unexpected.append(port)
        rows.append([port, LABEL[result], note])

    findings = [Finding(
        title=f"예상 밖으로 열려 있는 포트 {len(open_unexpected)}개",
        severity="medium", location=f"{host} (TCP)",
        evidence=f"밖에서 TCP 연결됨: {', '.join(str(p) for p in open_unexpected)}\n"
                 f"열려 있어도 되는 포트로 적어 둔 것: {', '.join(str(p) for p in sorted(expected)) or '없음'}",
        recommendation="보안 그룹·방화벽에서 필요한 곳에만 열고, 관리용 포트는 터널로만 닿게 합니다.",
    )] if open_unexpected else []

    return ToolResult(
        summary=f"{len(rows)}개 확인 · 열림 {sum(1 for r in rows if r[1] == '열림')}개"
                + (f" · 예상 밖 {len(open_unexpected)}개" if open_unexpected else ""),
        columns=["포트", "결과", "판단"], rows=rows, findings=findings,
        note="연결 요청만 보내고 바로 끊습니다. 대상 호스트의 적어 둔 포트에만 보냅니다.")
