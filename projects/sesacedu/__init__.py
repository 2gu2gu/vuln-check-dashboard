"""새싹에듀 모의해킹 프로젝트 팩."""

PROJECT = {
    "name": "새싹에듀 모의해킹",
    # 프로젝트 전체 범위. 역할을 고르면 아래 역할별 범위로 더 좁혀진다.
    "scope": ["sesacedu.store", "localhost", "127.0.0.1"],
    "description": "사용자 웹(EC2 ①) · 관리자 웹(EC2 ②, 터널) · Wazuh(EC2 ③, 터널)",
    # 관리자 웹과 Wazuh 는 SSH 터널로 둘 다 127.0.0.1 에 열린다.
    # 호스트만으로는 구분되지 않으므로 역할마다 포트까지 적어 둔다 —
    # 관리자 웹 대상으로 돌린 모듈이 Wazuh 포트로 나가지 못한다.
    "roles": {
        "user_web": {
            "name": "사용자 웹 (EC2 ①, sesacedu.store)",
            "scope": ["sesacedu.store"],
        },
        "admin_web": {
            "name": "관리자 웹 (EC2 ②, 터널 3000)",
            "scope": ["localhost:3000", "127.0.0.1:3000"],
        },
        "siem": {
            "name": "Wazuh (EC2 ③, 터널 8443)",
            "scope": ["localhost:8443", "127.0.0.1:8443"],
        },
        "practice": {
            "name": "연습용 대상 (demo_target.py, 5051)",
            "scope": ["localhost:5051", "127.0.0.1:5051"],
        },
    },
}
