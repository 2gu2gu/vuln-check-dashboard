# 사전(wordlist)

여기 있는 것은 **씨앗 목록**이다 — 우리 환경(Spring·Tomcat·Next·Oracle)에 맞춰 짧게 추렸다.
`seclists/` 에 SecLists 발췌 세 개를 함께 담아 뒀다(아래). 전체를 쓰려면 받아 두고 경로를
알려 주면 된다. 그러면 화면의 사전 목록에 같이 뜬다.

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
| `payload-reflect.txt` | 입력값 넣어 보기 | 특수문자가 걸러지는지 보는 짧은 입력 |
| `payload-sql-error.txt` | 입력값 넣어 보기 | DB 오류 메시지를 끌어내 보는 입력 |
| `fs-seeds-sesacedu.txt` | 자료 경로 조작 퍼징(씨앗) | 패키지를 깔면 생기는 전체 경로 115개. 11-04 실측에서 찾은 94개 중 55개가 여기서 나왔다 |
| `fs-dirnames.txt` | 자료 경로 조작 퍼징(사전) | 자바 웹 배포에서 쓰는 디렉터리·설정 파일 **이름** 159개. 확정된 디렉터리 아래를 넓힐 때 쓴다 |

페이로드는 **터지는지 보는 용도가 아니라, 걸러지는지 보는 용도**다.
`{T}` 는 보낼 때 그 요청의 표식으로 바뀐다 — 응답에서 되돌아온 자리를 찾는 데 쓴다.

## `seclists/` — SecLists 발췌 세 개

SecLists 는 칼리에 `/usr/share/seclists` 로 1.9 GB 들어 있다. 그런데 **대시보드는 윈도에서
돌아서 그 경로를 못 본다.** 팀원마다 2 GB 를 받게 하는 대신, 쓸 것 세 개(약 330 KB)만 담았다.

| 파일 | 줄 수 | 쓰는 곳 | 고른 이유 |
|---|---|---|---|
| `LFI-gracefulsecurity-linux.txt` | 881 | 퍼징(씨앗) | 리눅스 절대경로 목록. 우리 씨앗과 22개만 겹치고 859개가 새로 들어온다 — `/etc/ssh/ssh_host_dsa_key` 같은 것 |
| `raft-small-directories.txt` | 20,115 | 숨은 경로 찾기 · 퍼징(2단계 이름) | 실제 웹에서 긁은 디렉터리 이름. 우리 `fs-dirnames.txt` 는 159개뿐이다 |
| `raft-small-files.txt` | 11,424 | 숨은 경로 찾기 | 같은 출처의 파일 이름 |

**안 담은 것과 이유** (11-05 직접 열어 보고 판단)

- `LFI-etc-files-of-all-linux-packages.txt`(8,315줄) — 이름만 보면 가장 좋아 보이는데 열어 보니
  **nginx 0건 · systemd 0건**, tomcat 은 `tomcat4` 뿐이다. 데비안 옛 패키지 목록이라 우리
  대상(nginx·systemd·Tomcat 10·JDK 11 tarball)과 안 맞는다. 180요청을 쓰고 '아무것도 없다'는
  틀린 결론을 얻게 된다.
- `LFI-Jhaddix.txt` — `../` 와 `%00` 이 든 **페이로드**다. 올라가는 것과 인코딩은 모듈이 이미
  `인코딩` 항목으로 한다. 씨앗 자리에 넣으면 경로가 어긋난다.

**넓은 사전이 이긴 적은 없다.** 실측 94개 중 씨앗 55 · 사전 33 이었고, 나머지는 수확으로 나왔다.
넓은 목록은 **확정된 디렉터리 아래를 넓힐 때**(2단계) 값이 있다. 한 실행의 요청 상한은
화면의 '요청 상한' 으로 정한다(기본 1,300 · 최대 2,200) — 20,115줄짜리를 골라도 앞쪽
`limit` 줄까지만 쓰인다.

### raft 는 톰캣을 모른다 (11-06 측정)

11-04 실측에서 **확장 단계가 찾아낸 이름 16개**를 각 사전에 넣어 봤다. 사전에 이름이
없으면 그 경로는 영원히 안 나오므로, 이것이 사전의 값을 재는 직접적인 방법이다.

| 사전 | 줄 수 | 16개 중 담은 것 |
|---|---|---|
| `fs-dirnames.txt` (우리) | 159 | **16 / 16** |
| `raft-small-directories` + `raft-small-files` | 31,539 | 10 / 16 |

raft 가 **전부 놓치는 6개**가 이것이다 — `catalina.properties` · `context.xml` ·
`logging.properties` · `server.xml` · `tomcat-users.xml` · `web.xml`. 실측에서 이 여섯 이름이
`api/conf` 와 `web/conf` 두 곳에서 **11개 노드**를 열었다. 실제 웹에서 긁은 목록이라
`/conf/server.xml` 처럼 **웹으로는 안 보이는** 파일 이름이 들어 있지 않다.

SecLists 전체에도 없다. 칼리 `/usr/share/seclists` 를 뒤져 보면 톰캣 설정 파일을 적어 둔
목록이 없다 — `JavaServlets-Common.fuzz.txt` 는 3줄이고 `catalina` 가 0건,
`LFI-LFISuite-pathtotest-huge.txt`(9,550줄)도 `tomcat` 0건이다. 그래서 **네 번째 발췌를
담지 않았다.** 담을 것이 없다.

**결론: 씨앗·2단계 이름의 기본값은 우리 목록으로 둔다.** raft 는 우리 목록에 없는 이름
31,466개를 더 주므로, 모르는 영역(사람이 지은 디렉터리 이름)을 넓힐 때 바꿔 쓴다.

거꾸로, 넓다고 다 들어 있는 것도 아니다. `LFI-gracefulsecurity-linux.txt` 는 오래된 목록이라
`ssh_host_ed25519_key`·`ssh_host_rsa_key` 가 없다 — 그래서 요즘 이름은 `fs-seeds-sesacedu.txt`
에 직접 넣었다. 둘이 서로를 메운다(`tests/test_wordlists.py` 가 이 관계를 지킨다).

출처: [SecLists](https://github.com/danielmiessler/SecLists) (칼리 패키지 `2025.3-0kali1`,
파일은 2025-09-19). 상류 저장소는 MIT, 칼리 패키지의 `copyright` 는 CC-BY-SA 3.0 으로 적고 있다
— 어느 쪽이든 출처를 적어 두는 조건이라 여기 적는다. 내용은 **고치지 않고 그대로** 뒀다.
