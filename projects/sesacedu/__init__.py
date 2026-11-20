"""새싹에듀 모의해킹 프로젝트 팩."""

PROJECT = {
    "name": "새싹에듀 모의해킹",
    # 프로젝트 전체 범위. 역할을 고르면 아래 역할별 범위로 더 좁혀진다.
    "scope": ["sesacedu.store", "localhost", "127.0.0.1"],
    "description": "사용자 웹(EC2 ①, sesacedu.store) · 관리자 웹(EC2 ②, admin.sesacedu.store)",
    # 프로젝트 기간과 보고회 — 결과 탭 '진단 일정' 달력에 쓴다. 출처는 작업일지 1~2절(운영 계획안 대조 11-13).
    # 달력에는 중간보고와 최종보고회(마감) 두 날만 칠한다. 주간보고·수행계획서는 넣지 않는다(사용자 결정 11-20).
    # 프로젝트는 10-06(화)에 시작했지만 달력 1주차는 10-12(월) 주로 잡는다 — 월~일 한 주씩 7주,
    # 최종보고회 11-23(월)이 7주차 첫날이 된다(사용자 결정 11-20).
    "schedule": {
        "start": "2026-10-12", "end": "2026-11-23", "weeks": 7,
        "marks": [{"date": "2026-11-02", "label": "중간보고", "kind": "mid", "short": "중간"},
                  {"date": "2026-11-23", "label": "최종보고회", "kind": "final", "short": "최종"}],
        # 팀 작업 기록 — 그 주 월요일 날짜: [월, 화, 수, 목, 금, 토, 일] 작업량 0~4(0 안 함, 4 가장 많음).
        # 대시보드 DB 는 모듈을 돌린 날만 알아서, 사람이 일한 날은 여기 적는다. 달력은 이 값과
        # 진단 기록 중 진한 쪽으로 칠한다.
        # ⚠ 사용자 진술(11-20)로 채운 초안이다: '평일은 전부 작업, 양은 날마다 다름, 토요일은 연하게
        #   한 주 걸러, 일요일은 대개 안 함'. 날짜별 값은 실제 기록이 아니라 그 말을 따라 고른 것이다 —
        #   팀 작업일지와 맞춰 고쳐 쓴다.
        "worklog": {
            "2026-10-12": [2, 3, 3, 2, 2, 1, 0],
            "2026-10-19": [3, 2, 4, 3, 2, 0, 1],
            "2026-10-26": [2, 3, 3, 4, 3, 1, 0],
            "2026-11-02": [4, 3, 4, 3, 4, 0, 0],
            "2026-11-09": [3, 4, 3, 2, 3, 1, 1],
            "2026-11-16": [3, 4, 4, 3, 4, 0, 0],
        },
    },
    # 같은 호스트(터널이면 localhost, 운영이면 sesacedu.store 계열)에 여러 서버가 걸리므로
    # 역할마다 호스트와 포트를 함께 적어 둔다 — 한 역할로 돌린 모듈이 다른 서버로 나가지 못한다.
    # Wazuh(EC2 ③)는 우리 쪽 탐지 장비라 점검 대상이 아니다. 역할을 두지 않는다.
    # 로그인해서 토큰 받는 법. 비밀번호는 저장하지 않고 받은 토큰만 인증 헤더에 넣는다.
    # 주소는 08_모의해킹/file_inclusion/fsmap/core/probe.py 가 쓰는 것과 같다.
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
        # 사용자 API 는 토큰을 응답 **헤더**로 준다(11-06 실서버 실측: 200 + Authorization: Bearer eyJ…,
        # 본문에는 result.member 뿐). 관리자 API 는 반대라 역할 쪽에서 빈 값으로 덮는다.
        "token_header": "Authorization",
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
            # 관리자는 **다른 서버로 로그인한다.** 관리자 API 는 ② 안쪽 127.0.0.1:8080 에 따로
            # 떠 있는 별개 Spring 앱(SesacEdu_Admin_Server)이고, 바깥에서는 관리자 웹(Next.js)이
            # /api/* 를 그쪽으로 넘겨 주는 길로만 닿는다(SesacEdu_Admin_Web/next.config.mjs:
            # rewrites /api/:path* → ${ADMIN_API_URL}/:path*). 그래서 칠 주소는 /api/admin/login 이다.
            # Spring 핸들러 자체는 POST /admin/login 이지만 그건 ② 안에서만 유효하다.
            "login": {
                "path": "/api/admin/login",
                # 사용자 API 는 email, 관리자 API 는 id 다(AdminLoginController 의 LoginRequest{id, pw}).
                # 값은 둘 다 users.mail 이다.
                "json": {"id": "{id}", "pw": "{secret}"},
                # 관리자 API 는 토큰을 **본문**으로 준다 — LoginResponse{userId, role, token,
                # authorizationHeader}. 응답 헤더로는 안 준다. 그래서 token_header 를 비운다.
                "token_keys": ["token", "authorizationHeader"],
                "token_header": "",
                "id_label": "관리자 이메일",
                "note": "**관리자 API 는 사용자 웹과 다른 서버입니다**(EC2 ② 안쪽 8080). "
                        "그래서 사용자 웹에서 받은 토큰은 여기서 안 통합니다 — 서명키가 다릅니다. "
                        "관리자 계정(auth=3)이어야 관리자 화면 API 가 열립니다. "
                        "**테스트 계정만 쓰세요.** 비밀번호는 저장하지 않습니다 — 한 번 보내고 버립니다.",
            },
        },
        "practice": {
            "name": "연습용 대상 (demo_target.py, 5051)",
            "scope": ["localhost:5051", "127.0.0.1:5051"],
            # 점검 대상이 아니다 — 우리가 띄운 가짜 서버다. 화면·보고서에서 실제 대상
            # 두 개와 같은 묶음에 두면 '이것도 점검했나요' 를 부른다.
            "practice": True,
        },
    },
}
