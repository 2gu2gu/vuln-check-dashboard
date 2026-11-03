"""새싹에듀 모의해킹 프로젝트 팩."""

PROJECT = {
    "name": "새싹에듀 모의해킹",
    # 관리자 웹(EC2 ②)·Wazuh(EC2 ③)는 SSH 터널로 127.0.0.1 에 열어 점검한다.
    # 그래서 호스트만으로는 서로 구분되지 않는다 — 대상마다 아래 역할을 골라 둔다.
    "scope": ["sesacedu.store", "localhost", "127.0.0.1"],
    "description": "사용자 웹(EC2 ①) · 관리자 웹(EC2 ②, 터널) · Wazuh(EC2 ③, 터널)",
    "roles": {
        "user_web": "사용자 웹 (EC2 ①, sesacedu.store)",
        "admin_web": "관리자 웹 (EC2 ②, 터널 localhost:3000)",
        "siem": "Wazuh (EC2 ③, 터널 localhost:8443)",
        "practice": "연습용 대상 (demo_target.py)",
    },
}
