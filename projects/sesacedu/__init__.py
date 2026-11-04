"""새싹에듀 모의해킹 프로젝트 팩."""

PROJECT = {
    "name": "새싹에듀 모의해킹",
    # 프로젝트 전체 범위. 역할을 고르면 아래 역할별 범위로 더 좁혀진다.
    "scope": ["sesacedu.store", "localhost", "127.0.0.1"],
    "description": "사용자 웹(EC2 ①, sesacedu.store) · 관리자 웹(EC2 ②, admin.sesacedu.store)",
    # 같은 호스트(터널이면 localhost, 운영이면 sesacedu.store 계열)에 여러 서버가 걸리므로
    # 역할마다 호스트와 포트를 함께 적어 둔다 — 한 역할로 돌린 모듈이 다른 서버로 나가지 못한다.
    # Wazuh(EC2 ③)는 우리 쪽 탐지 장비라 점검 대상이 아니다. 역할을 두지 않는다.
    # 로그인해서 토큰 받는 법. 비밀번호는 저장하지 않고 받은 토큰만 인증 헤더에 넣는다.
    # 주소는 08_모의해킹/file_inclution/fsmap/core/probe.py 가 쓰는 것과 같다.
    "login": {
        "path": "/backend/login",
        "json": {"email": "{id}", "pw": "{secret}"},
        # 이 API 의 봉투는 {code, message, result} 다(11-05 실측: 빈 로그인 요청의 400 응답).
        # result 아래를 안 보고 있어서 토큰을 못 찾고 있었다.
        "token_keys": ["result.token", "result.accessToken", "result.access_token",
                       "result.authorizationHeader", "token", "accessToken", "access_token",
                       "authorizationHeader", "data.token", "data.accessToken"],
        "header": "Authorization",
        "prefix": "Bearer ",
        # 연습용 대상(demo_target.py)도 같은 주소·같은 봉투로 토큰을 준다.
        "roles": ["user_web", "practice"],
        # 연습용 서버의 계정은 화면에 그대로 띄운다 — 가짜고, 안 보이면 돌려 볼 수가 없다.
        # 실서버 역할에는 넣지 않는다. 사람이 자기 테스트 계정을 직접 넣는다.
        "demo_accounts": {"practice": {"ident": "demo@sesacedu.test", "secret": "demo1234",
                                       "note": "연습용 서버의 가짜 계정입니다. 그대로 두고 눌러 보세요."}},
        "id_label": "이메일",
        "note": "**테스트 계정만 쓰세요.** 비밀번호는 저장하지 않습니다 — 한 번 보내고 버리고, "
                "요청 기록에도 남기지 않습니다. 받아 온 토큰만 이 대상의 인증 헤더에 들어갑니다.",
    },
    "roles": {
        "user_web": {
            "name": "사용자 웹 (EC2 ①, sesacedu.store)",
            # '=' 는 그 호스트만 — admin.sesacedu.store 로는 못 나간다
            "scope": ["=sesacedu.store", "=www.sesacedu.store"],
        },
        "admin_web": {
            # 11-04 8443 포트를 닫고 서브도메인으로 옮겼다. nginx 가 접속 이름(SNI)으로 가른다.
            # 터널(localhost:3000)도 아직 살아 있어 둘 다 둔다.
            "name": "관리자 웹 (EC2 ②, admin.sesacedu.store)",
            "scope": ["=admin.sesacedu.store", "localhost:3000", "127.0.0.1:3000"],
        },
        "practice": {
            "name": "연습용 대상 (demo_target.py, 5051)",
            "scope": ["localhost:5051", "127.0.0.1:5051"],
        },
    },
}
