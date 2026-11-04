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
게다가 한 실행의 요청 상한이 400개여서 20,115줄짜리를 골라도 앞쪽 `limit` 줄만 쓰인다.
넓은 목록은 **확정된 디렉터리 아래를 넓힐 때**(2단계) 값이 있다.

거꾸로, 넓다고 다 들어 있는 것도 아니다. `LFI-gracefulsecurity-linux.txt` 는 오래된 목록이라
`ssh_host_ed25519_key`·`ssh_host_rsa_key` 가 없다 — 그래서 요즘 이름은 `fs-seeds-sesacedu.txt`
에 직접 넣었다. 둘이 서로를 메운다(`tests/test_wordlists.py` 가 이 관계를 지킨다).

출처: [SecLists](https://github.com/danielmiessler/SecLists) (칼리 패키지 `2025.3-0kali1`,
파일은 2025-09-19). 상류 저장소는 MIT, 칼리 패키지의 `copyright` 는 CC-BY-SA 3.0 으로 적고 있다
— 어느 쪽이든 출처를 적어 두는 조건이라 여기 적는다. 내용은 **고치지 않고 그대로** 뒀다.
