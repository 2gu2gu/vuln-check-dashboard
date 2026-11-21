"""관찰한 버전 → CVE 후보. 수사보드의 후보 목록에 올라가는 재료.

레드팀은 밖에서 시작한다. 배너·오류 페이지에서 본 '제품/버전' 이 다음 공격을 고르는 단서다.
여기서는 그 단서를 결과 행에서 뽑고(observe), 두 곳에서 CVE 를 찾는다.

    팀 목록   projects/<id>/cve_team.py 의 CVE_TEAM — 팀이 실제로 다룬 것, 문서의 상태 그대로
    NVD      미국 NIST 국가 취약점 DB. 제품·버전을 넣으면 '이 버전이 범위에 드는' CVE 를 준다

## 섞지 않는 것

NVD 결과는 버전 범위가 맞는다는 뜻일 뿐이다. 배너 버전은 틀릴 수 있고(Ubuntu nginx 는 번호를
그대로 두고 패치만 넣는다), 설정 조건이 안 맞으면 안 된다. 그래서 NVD 후보는 늘 **추정**이고,
팀 목록에 있으면 그 상태(확인·코드 확인)로 덮는다. 팀 목록에 없는 것을 '확인' 으로 올리지 않는다.

## 밖으로 나가는 요청

NVD 조회는 점검 대상이 아니라 services.nvd.nist.gov 로 나간다. 그래서 화면을 열 때마다 묻지
않고 **버튼을 누를 때만** 묻고, 받은 것은 nvd_cache 에 남겨 다시 쓴다. 보내는 것은
`cpe:2.3:a:apache:tomcat:10.1.1` 같은 제품·버전 문자열뿐이다.
키 없이 30초에 5번까지라 제품 사이에 쉬어 간다.
"""
import importlib
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAUSE_S = 6.5          # 키 없는 한도 5회/30초
USER_AGENT = "ttalkkak-dast/0.2"

# 결과 증거에서 '제품/버전' 을 찾는다. 긴 이름을 앞에 둬야 'Apache Tomcat' 이 'Apache' 로 잘리지 않는다.
VERSION_RE = re.compile(
    r"(Apache Tomcat|Apache-Coyote|Microsoft-IIS|Next\.js|Node\.js|OpenSSL|OpenSSH|Werkzeug|Express|Jetty|"
    r"Spring Boot|Spring Framework|log4j-core|MariaDB|MySQL|nginx|Apache|Python|PHP)"
    r"[/ _]v?(\d+(?:\.\d+)+)(?:\s*\(([^)]{1,30})\))?", re.I)

# 읽어 낸 **경로·파일 이름**에서도 버전을 뽑는다(11-22 사용자 지시: 얻은 정보에서 추론해 CVE 를 쫓아라).
# 경로 조작으로 읽은 파일 목록에는 `/opt/apache-tomcat-10.1.1/...`, `/usr/lib/jvm/java-17-openjdk-amd64`
# 처럼 **버전이 박힌 경로**가 그대로 들어 있다. 배너가 없어도 이것만으로 제품·버전을 알 수 있다.
PATH_RE = [
    (re.compile(r"apache-tomcat-(\d+(?:\.\d+)+)"), "apache tomcat"),
    (re.compile(r"tomcat-?(\d+(?:\.\d+)+)/"), "apache tomcat"),
    (re.compile(r"jvm/java-(\d+)(?:[.\-]\S*)?-openjdk"), "openjdk"),
    (re.compile(r"openjdk[-_](\d+(?:\.\d+)*)"), "openjdk"),
    (re.compile(r"openssh[-_](\d+(?:\.\d+)+)"), "openssh"),
    (re.compile(r"log4j-core-(\d+(?:\.\d+)+)"), "log4j-core"),
    (re.compile(r"spring-core-(\d+(?:\.\d+)+)"), "spring framework"),
    (re.compile(r"spring-boot-(\d+(?:\.\d+)+)"), "spring boot"),
    (re.compile(r"nginx-(\d+(?:\.\d+)+)"), "nginx"),
    (re.compile(r"python(\d+\.\d+)/"), "python"),
]

# 제품 → NVD CPE (vendor, product). nginx 는 2022년 무렵부터 f5 이름으로 올라간다.
PRODUCTS = {
    "apache tomcat": ("Apache Tomcat", [("apache", "tomcat")]),
    "nginx": ("nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    "apache": ("Apache httpd", [("apache", "http_server")]),
    "jetty": ("Jetty", [("eclipse", "jetty")]),
    "microsoft-iis": ("Microsoft IIS", [("microsoft", "internet_information_services")]),
    "express": ("Express", [("expressjs", "express"), ("openjsf", "express")]),
    "werkzeug": ("Werkzeug", [("palletsprojects", "werkzeug")]),
    "python": ("Python", [("python", "python")]),
    "php": ("PHP", [("php", "php")]),
    "next.js": ("Next.js", [("vercel", "next.js")]),
    "node.js": ("Node.js", [("nodejs", "node.js")]),
    "openssl": ("OpenSSL", [("openssl", "openssl")]),
    # 경로·파일 이름에서 얻는 것들(11-22). 운영체제는 CPE 의 part 가 `o` 다
    "openjdk": ("OpenJDK", [("oracle", "jdk"), ("oracle", "openjdk"), ("redhat", "openjdk")]),
    "openssh": ("OpenSSH", [("openbsd", "openssh")]),
    "log4j-core": ("log4j-core", [("apache", "log4j")]),
    "spring framework": ("Spring Framework", [("vmware", "spring_framework"),
                                              ("pivotal_software", "spring_framework")]),
    "spring boot": ("Spring Boot", [("vmware", "spring_boot"), ("pivotal_software", "spring_boot")]),
    "mysql": ("MySQL", [("oracle", "mysql")]),
    "mariadb": ("MariaDB", [("mariadb", "mariadb")]),
    "ubuntu": ("Ubuntu", [("canonical", "ubuntu_linux", "o")]),
}


# 제품 이름이 결과에 그대로 안 나오는 경우가 많다 — 별명으로도 찾는다(11-22, 캠페인 선 긋기).
# 예: Log4Shell 점검 결과의 제목은 'jndi 조회…' 라 'log4j-core' 라는 글자가 없다.
NICKNAMES = {
    "log4j-core": ["log4j", "log4shell", "jndi"],
    "apache tomcat": ["tomcat", "catalina", "coyote"],
    "spring framework": ["spring"],
    "spring boot": ["spring boot", "actuator"],
    "next.js": ["next.js", "_next", "rsc"],
    "openjdk": ["openjdk", "jvm", "java-"],
    "openssh": ["openssh", "sshd"],
    "swagger-ui": ["swagger", "api-docs"],
    "snakeyaml": ["yaml"],
    "nginx": ["nginx"],
    "ubuntu": ["ubuntu"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb"],
}


def nicknames(product: str) -> list:
    """제품 이름 → 결과에서 찾아볼 글자들(소문자)."""
    p = (product or "").strip().lower()
    for key, words in NICKNAMES.items():
        if p.startswith(key):
            return words
    head = p.split(" ")[0]
    return [head] if len(head) > 2 else []


def observe(findings):
    """결과 행들 → [{product, version, distro, finding_id, title, location, how}] (제품·버전마다 하나).

    두 곳에서 본다.
        배너·본문   `Server: nginx/1.24.0`, `Apache Tomcat/10.1.1` 같은 글자 (how='배너')
        읽은 경로   `/opt/apache-tomcat-10.1.1/...` 처럼 **버전이 박힌 경로** (how='읽은 경로')

    경로 쪽은 경로 조작으로 읽어 낸 파일 목록에서 나온다 — 배너를 지워도 남는 단서다
    (11-22 사용자 지시: 얻은 정보에서 추론해 CVE 를 쫓아라).
    """
    seen = {}

    def put(key, version, f, how, distro=""):
        if key not in PRODUCTS:
            return                             # Apache-Coyote 처럼 버전이 의미 없는 이름
        name = PRODUCTS[key][0]
        k = (name, version)
        if k not in seen:
            seen[k] = {"product": name, "key": key, "version": version, "distro": distro,
                       "finding_id": f["id"], "title": f["title"], "location": f["location"], "how": how}

    for f in findings:
        body = f["evidence"] or ""
        for m in VERSION_RE.finditer(body):
            put(m.group(1).lower(), m.group(2), f, "배너", m.group(3) or "")
        for pat, key in PATH_RE:
            for m in pat.finditer(body):
                put(key, m.group(1), f, "읽은 경로")
    return list(seen.values())


def team_list(target, projects_pkg="projects"):
    """그 대상의 프로젝트 팩에 있는 팀 CVE 중 대상 역할에 걸린 것."""
    if not target or not target["project"]:
        return []
    try:
        mod = importlib.import_module(f"{projects_pkg}.{target['project']}.cve_team")
    except ModuleNotFoundError:
        return []
    role = target["role"] if "role" in target.keys() else ""
    return [dict(c) for c in getattr(mod, "CVE_TEAM", []) if not c.get("roles") or role in c["roles"]]


# ── NVD ──────────────────────────────────────────────────

def cpe(vendor, product, version, part="a"):
    """NVD 에 보낼 제품 글자. 운영체제(Ubuntu)는 part 가 `o` 라 따로 받는다(11-22)."""
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}"


def _slim(item):
    """NVD 응답의 CVE 하나 → 화면에 필요한 것만."""
    c = item["cve"]
    m = c.get("metrics", {})
    metric = (m.get("cvssMetricV31") or m.get("cvssMetricV30") or [{}])[0].get("cvssData", {})
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"id": c["id"], "score": metric.get("baseScore"), "severity": (metric.get("baseSeverity") or "").lower(),
            "vector": metric.get("vectorString", ""), "kev": bool(c.get("cisaExploitAdd")),
            "published": (c.get("published") or "")[:10], "summary": desc[:240]}


def fetch_nvd(cpe_name, opener=None, timeout=30):
    """CPE 하나로 NVD 를 묻는다. 버전 범위로 맞는 CVE 전부(최대 2000)."""
    q = urllib.parse.urlencode({"virtualMatchString": cpe_name, "resultsPerPage": 2000})
    req = urllib.request.Request(f"{NVD_URL}?{q}", headers={"User-Agent": USER_AGENT})
    with (opener or urllib.request.urlopen)(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    return [_slim(v) for v in data.get("vulnerabilities", [])]


def cached(db, cpe_name):
    row = db.execute("SELECT body, fetched_at FROM nvd_cache WHERE cpe = ?", [cpe_name]).fetchone()
    return (json.loads(row["body"]), row["fetched_at"]) if row else (None, None)


def refresh(db, observed, fetch=fetch_nvd, pause=NVD_PAUSE_S):
    """관찰한 제품마다 NVD 를 물어 nvd_cache 에 넣는다. (물은 수, 실패 [(cpe, 이유)])"""
    asked, failed = 0, []
    for o in observed:
        for vendor, product, *part in PRODUCTS[o["key"]][1]:
            name = cpe(vendor, product, o["version"], part[0] if part else "a")
            if asked:
                time.sleep(pause)
            asked += 1
            try:
                rows = fetch(name)
            except Exception as e:             # 네트워크가 막힌 서버에서도 화면은 떠야 한다
                failed.append((name, str(e)[:120]))
                continue
            db.execute("INSERT OR REPLACE INTO nvd_cache (cpe, body, fetched_at) VALUES (?, ?, ?)",
                       [name, json.dumps(rows, ensure_ascii=False), datetime.now(timezone.utc).isoformat()])
    db.commit()
    return asked, failed


# ── 후보 목록 ─────────────────────────────────────────────

def candidates(db, target, findings, projects_pkg="projects"):
    """수사보드 후보 목록의 CVE 부분.

    {"observed": [...관찰한 버전, 각자 nvd 결과 붙음...], "team": [...], "asked": NVD 를 물어 둔 게 있나}
    팀 목록에 있는 CVE 는 NVD 후보에서 '팀' 표시로 바뀌고, 팀 목록은 따로도 보인다
    (Log4Shell 처럼 밖에서 버전이 안 보이는 것도 있어서).
    """
    observed = observe(findings)
    team = team_list(target, projects_pkg)
    team_ids = {c["id"]: c for c in team if c["id"]}
    seen_versions = {(o["product"].lower(), o["version"]) for o in observed}
    for c in team:
        c["seen_now"] = (c["product"].lower(), c["version"]) in seen_versions
    asked = False
    for o in observed:
        rows, when = [], None
        for vendor, product, *part in PRODUCTS[o["key"]][1]:
            got, at = cached(db, cpe(vendor, product, o["version"], part[0] if part else "a"))
            if got is not None:
                asked = True
                when = max(when or at, at)
                rows += [r for r in got if r["id"] not in {x["id"] for x in rows}]
        for r in rows:
            t = team_ids.get(r["id"])
            r["status"] = t["status"] if t else "추정"
            r["team"] = bool(t)
        # 팀이 다룬 것 → 실제 악용 목록(KEV) → 점수 순
        rows.sort(key=lambda r: (not r["team"], not r["kev"], -(r["score"] or 0)))
        o["cves"], o["asked_at"] = rows, when
        o["asked"] = when is not None
    return {"observed": observed, "team": team, "asked": asked}
