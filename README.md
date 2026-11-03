# vuln-check-dashboard — 점검 대시보드 (프로토타입)

자체 실습 환경을 대상으로 점검 모듈을 버튼으로 돌리고, 결과를 MITRE ATT&CK 전술·기법으로 묶어 보는 로컬 웹 도구다. Flask + SQLite. 127.0.0.1 에서만 연다.
앱 본체와 범용 모듈은 특정 서비스를 모르고, 서비스별 점검은 프로젝트 팩으로 붙인다. 지금 들어 있는 팩은 새싹에듀 모의해킹 프로젝트(`projects/sesacedu/`) 하나다.

## 실행

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run.py          # http://127.0.0.1:5050
.\.venv\Scripts\python.exe -m pytest -q    # 테스트
```

데이터는 `instance/dashboard.sqlite3` 에 쌓인다. 지우면 처음 상태로 돌아간다.

## 화면

| 탭 | 하는 일 |
|---|---|
| 결과 | 심각도 요약 카드, 필터(심각도·모듈·상태), 표, 행을 누르면 오른쪽 상세(근거·조치·상태 변경) |
| 대상 | 프로젝트를 골라 대상 주소 등록. 프로젝트 범위 밖 주소는 거부 |
| 모듈 | 범용 / 프로젝트 전용으로 나눠 보이고, 대상에 바로 실행. 불러오기 실패한 모듈도 여기 표시 |
| ATT&CK | 14개 전술 매트릭스. 모듈이 다루는 기법만 칸으로, 이 대상에서 발견된 기법은 강조 |
| 시나리오 | 미확인·확인됨 결과를 전술 순서로 늘어놓은 초안 |
| 보고서 | 위쪽 버튼으로 Markdown 내려받기 |

## 구조: 범용은 고정, 프로젝트 것은 갈아끼운다

```
modules/                       범용 모듈 — 어느 대상에나 보인다
  _template.py                 새 모듈 작성 틀(_ 로 시작해 등록 안 됨)
  http_security_headers.py
  tech_fingerprint.py
projects/
  sesacedu/                    프로젝트 팩 하나 = 폴더 하나
    __init__.py                PROJECT = {name, scope, description}
    modules/
      exposed_paths.py         새싹에듀 구성(Tomcat·Spring)을 아는 전용 모듈
dashboard/                     앱 본체(대상·실행·저장·화면) — 모듈 추가로는 손대지 않는다
```

- 대상은 등록할 때 프로젝트에 묶인다. 그 대상을 고르면 **범용 + 그 프로젝트 전용** 모듈만 보이고, 요청 범위도 그 프로젝트 `scope` 로 걸린다.
- 다른 서비스를 점검하게 되면 `projects/<새이름>/` 폴더를 만들고 `__init__.py` 에 `PROJECT` 를 쓰면 된다. 앱 코드는 바꾸지 않는다.
- 범용 모듈에는 특정 프로젝트의 주소·경로·계정을 넣지 않는다. 그런 건 프로젝트 팩으로.
- 모듈 `id` 는 범용·모든 프로젝트를 통틀어 하나여야 한다(겹치면 화면에 오류로 뜨고 뒤의 것은 빠진다).

## 모듈 추가

1. `modules/_template.py` 를 복사해 범용이면 `modules/`, 전용이면 `projects/<프로젝트>/modules/` 에 둔다.
2. `META` 를 채운다.
   - `kind`: `passive`(읽기만) / `active`(실행 전 "자체 환경 확인" 체크 필요)
   - `attack`: `[{tactic: "TA0043", technique: "T1595.002", name: ...}]` — 매트릭스·시나리오가 이걸로 그려진다
   - `params`: 화면 입력칸
3. `run(target, params)` 에서 `Finding` 목록을 돌려준다.
4. 다시 실행하면 등록된다.

기존 파이썬 도구를 감싸는 모듈도 같은 틀이다. `run()` 안에서 도구를 부르고 결과를 `Finding` 으로 바꾸면 된다. 이때 도구가 직접 요청을 보낸다면 대상 주소를 `scope.ensure_in_scope(url)` 로 먼저 검사한다.

## 안전장치

- 모든 요청은 `core.fetch` 를 거친다. 실행 중인 대상 프로젝트의 `scope` 밖이면 보내기 전에 막고, 리다이렉트는 따라가지 않는다.
- 앱은 127.0.0.1 에만 연다.
- 근거(evidence)에 쿠키 값·`.env` 내용 같은 비밀값을 남기지 않는다. 이름·상태코드·길이만.
- 모듈 하나가 깨져도 나머지는 뜬다. 실행 실패도 실행 기록에 남는다.

## 브랜치

- `main`: 동작이 확인된 것만. `dev`: 통합.
- 작업은 최신 `dev` 에서 `feat/[기능]` 브랜치를 따서 하고, PR 은 `dev` 로. `main`·`dev` 에 직접 push 하지 않는다.
- 커밋 메시지: `타입:[기능] 설명` (예: `feat:[module] robots.txt 점검 추가`)

## 남은 것

- 실행은 동기(요청 안에서 끝날 때까지 기다림). 오래 걸리는 모듈이 생기면 백그라운드 실행으로 바꾼다.
- 시나리오는 전술 순서 정렬까지만. 결과끼리 연결(이 발견 → 다음 단계)하는 편집 기능은 없다.
- 보고서는 Markdown 만. Word 변환은 필요할 때.
