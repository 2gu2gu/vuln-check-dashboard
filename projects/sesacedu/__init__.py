"""새싹에듀 모의해킹 프로젝트 팩."""

PROJECT = {
    "name": "새싹에듀 모의해킹",
    # 관리자 웹(EC2 ②)은 SSH 터널로 127.0.0.1 에 열어 점검한다
    "scope": ["sesacedu.store", "localhost", "127.0.0.1"],
    "description": "사용자 웹(EC2 ①) · 관리자 웹(EC2 ②, 터널)",
}
