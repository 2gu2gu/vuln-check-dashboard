# 사전(wordlist)

여기 있는 것은 **씨앗 목록**이다 — 우리 환경(Spring·Tomcat·Next·Oracle)에 맞춰 짧게 추렸다.
본격적으로 쓰려면 SecLists 를 받아 두고 경로를 알려 주면 된다. 그러면 화면의 사전 목록에 같이 뜬다.

```powershell
git clone --depth 1 https://github.com/danielmiessler/SecLists C:\tools\SecLists
$env:DASH_WORDLISTS = "C:\tools\SecLists\Discovery\Web-Content;C:\tools\SecLists\Fuzzing"
.\.venv\Scripts\python.exe run.py
```

- 여러 폴더는 `;`(윈도) 또는 `:`(리눅스)로 잇는다.
- `.txt` 파일만 읽고, 하위 폴더도 한 단계까지 본다.
- `#` 로 시작하는 줄과 빈 줄은 건너뛴다.
- 한 번에 읽는 줄 수에 한도가 있다(화면의 '몇 개까지'). 큰 목록을 통째로 쏘지 않기 위해서다.

## 들어 있는 것

| 파일 | 쓰는 곳 | 내용 |
|---|---|---|
| `web-common.txt` | 숨은 경로 찾기 | 흔한 웹 경로·관리 화면 |
| `web-spring-tomcat.txt` | 숨은 경로 찾기 | Spring Boot·Tomcat 구성에서 나오는 경로 |
| `backup-config.txt` | 숨은 경로 찾기 | 백업·설정 파일 이름(지워야 할 것들) |
| `payload-reflect.txt` | 패턴 넣어 보기 | 특수문자가 걸러지는지 보는 짧은 입력 |
| `payload-sql-error.txt` | 패턴 넣어 보기 | DB 오류 메시지를 끌어내 보는 입력 |

페이로드는 **터지는지 보는 용도가 아니라, 걸러지는지 보는 용도**다.
`{T}` 는 보낼 때 그 요청의 표식으로 바뀐다 — 응답에서 되돌아온 자리를 찾는 데 쓴다.
