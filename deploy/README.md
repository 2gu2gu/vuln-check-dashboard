# 서버에 올리기 (Ubuntu + nginx + systemd)

딸깍이는 본래 **내 PC 에서 혼자 쓰는 도구**다. 서버에 올려 밖에서 열면 전제가 하나 깨진다 —
`Host` 검사가 로컬 이름만 받던 자리를 열어야 한다(`DASH_ALLOWED_HOSTS`). 그 외에는 같다.

**이 설정에는 로그인이 없다.** 주소를 아는 사람은 누구나 화면을 열고, 저장된 대상·토큰을 보고,
실행 버튼을 누를 수 있다. 공개 주소로 열 거라면 그 사실을 알고 열어야 한다.

## 1. 올리기

```bash
sudo apt update && sudo apt install -y python3-venv nginx git
# -m 을 주지 않는다 — 홈 디렉터리는 아래 clone 이 만든다(먼저 만들면 skel 파일 때문에 clone 이 거절된다)
sudo useradd -r -d /opt/ttalkkak -s /usr/sbin/nologin ttalkkak
sudo git clone <저장소 주소> /opt/ttalkkak
sudo chown -R ttalkkak:ttalkkak /opt/ttalkkak
cd /opt/ttalkkak
sudo -u ttalkkak python3 -m venv .venv
sudo -u ttalkkak .venv/bin/pip install -r requirements.txt
```

## 2. 서비스로 띄우기

```bash
sudo cp deploy/ttalkkak.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ttalkkak
systemctl status ttalkkak --no-pager
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5050/      # 200
```

들어올 이름은 유닛 파일의 `DASH_ALLOWED_HOSTS` 에 적는다. 이름 대신 공인 IP 로 들어오고
그 IP 가 바뀔 수 있으면 `*` 로 둔다(이름 검사를 끄는 것과 같다).

## 3. 앞에 nginx

```bash
sudo cp deploy/nginx-ttalkkak.conf /etc/nginx/sites-available/ttalkkak
sudo ln -sf /etc/nginx/sites-available/ttalkkak /etc/nginx/sites-enabled/ttalkkak
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

`proxy_read_timeout` 을 900초로 둔 이유: 도구 실행은 요청 안에서 끝까지 돈다. 경로 조작 퍼징은
실측 67초였고 범위가 넓으면 몇 분이다. 기본 60초면 **멀쩡히 도는 실행이 504 로 잘린다.**

## 4. 점검 대상에 닿는지

대상 쪽이 출발지 IP 를 가리고 있으면(nginx `allow`, 보안 그룹) **서버의 공인 IP** 를 허용 목록에
넣어야 한다. 내 PC 를 넣어 둔 것과는 별개다 — 이제 요청은 서버에서 나간다.

## 바뀐 코드

| 환경변수 | 기본 | 뜻 |
|---|---|---|
| `DASH_ALLOWED_HOSTS` | (없음) | 들어와도 되는 Host 이름. 쉼표로 여러 개, `*` 는 전부. 로컬 이름은 늘 통과 |
| `DASH_BIND` | 127.0.0.1 | 앱이 열 주소. nginx 를 앞에 두면 그대로, 없으면 `0.0.0.0` |

## 올린 뒤에도 그대로인 것

- 자기 점검 차단(`SELF_PORT`), 범위 밖 차단, CSRF, 요청 간격·한도는 전과 같다.
- 데이터는 `instance/dashboard.sqlite3` 하나다. 백업·이전은 이 파일을 옮기면 된다.
