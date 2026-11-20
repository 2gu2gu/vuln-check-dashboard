"""MITRE ATT&CK Enterprise 전술 15개(공격 진행 순서).

ATT&CK content v20.1 기준(11-20 attack.mitre.org/tactics/enterprise 에서 확인).
v20 에서 TA0005 이름이 Defense Evasion → Stealth 로 바뀌고 TA0112 Defense Impairment 가 새로 생겼다.
판이 바뀌면 이 목록과 보고서(결과보고서 양식 G-6 등)를 같이 고친다.
"""

TACTICS = [
    ("TA0043", "Reconnaissance", "정찰"),
    ("TA0042", "Resource Development", "자원 개발"),
    ("TA0001", "Initial Access", "초기 접근"),
    ("TA0002", "Execution", "실행"),
    ("TA0003", "Persistence", "지속성"),
    ("TA0004", "Privilege Escalation", "권한 상승"),
    ("TA0005", "Stealth", "은폐"),
    ("TA0112", "Defense Impairment", "방어 무력화"),
    ("TA0006", "Credential Access", "자격 증명 접근"),
    ("TA0007", "Discovery", "탐색"),
    ("TA0008", "Lateral Movement", "내부 이동"),
    ("TA0009", "Collection", "수집"),
    ("TA0011", "Command and Control", "명령 및 제어"),
    ("TA0010", "Exfiltration", "유출"),
    ("TA0040", "Impact", "영향"),
]

TACTIC_ORDER = {tid: i for i, (tid, _, _) in enumerate(TACTICS)}
TACTIC_NAME = {tid: ko for tid, _, ko in TACTICS}


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
