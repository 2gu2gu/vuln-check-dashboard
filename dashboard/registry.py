"""모듈·프로젝트 팩을 자동으로 찾아 등록한다. 이름이 _ 로 시작하는 파일·폴더는 건너뛴다.

modules/                 범용 모듈 — 어느 대상에나 보인다(고정)
projects/<id>/__init__.py  프로젝트 팩 — PROJECT = {name, scope, description}
projects/<id>/modules/   그 프로젝트 대상에만 보이는 전용 모듈
"""
import importlib
import importlib.util
import pkgutil
from dataclasses import dataclass, field

from .attack import TACTIC_ORDER
from .core import SEVERITIES

REQUIRED = ("id", "name", "category", "kind", "attack", "description")
KINDS = ("passive", "active")
# collect: run(target, params) → [Point]  표면 수집
# check:   run(target, params) → [Finding]  대상 단위 점검(기본)
# probe:   run(target, points, params) → [Check]  수집된 지점 단위 점검
# tool:    run(target, params) → ToolResult  도구 탭에서 값을 넣고 바로 결과를 보는 것
STAGES = ("collect", "check", "probe", "tool")
STAGE_LABEL = {"collect": "표면 수집", "check": "대상 점검", "probe": "지점 점검", "tool": "도구"}
GENERAL = "general"  # 어느 프로젝트에도 속하지 않는 대상
# 연습용 묶음 이름. 프로젝트 이름을 쓰지 않는 것이 요점이다 — 점검 범위가 아니다.
PRACTICE_LABEL = "연습용 — 점검 대상 아님"


@dataclass
class ModuleInfo:
    id: str
    name: str
    category: str
    kind: str
    attack: list
    description: str
    run: object
    params: list = field(default_factory=list)
    source: str = ""
    project: str = ""  # "" = 범용
    roles: list = field(default_factory=list)  # 비우면 어떤 역할의 대상에도 보인다
    stage: str = "check"
    severity: str = "medium"  # probe 가 '취약'을 낼 때 기본 심각도
    needs: list = field(default_factory=list)  # 실행 전에 미리 준비해야 하는 것(토큰·환경변수 등)
    cvss: str = ""  # 이 모듈이 찾는 것의 전형적인 CVSS 벡터(제안값 — 사람이 고쳐 쓴다)
    vuln: str = "기타"  # 노션 '웹 서비스 취약점 목록' 의 취약점 유형

    @property
    def stage_label(self) -> str:
        return STAGE_LABEL[self.stage]

    @property
    def first_tactic_order(self) -> int:
        return min((TACTIC_ORDER.get(a["tactic"], 99) for a in self.attack), default=99)


@dataclass
class ProjectInfo:
    id: str
    name: str
    scope: list
    description: str = ""
    source: str = ""
    roles: dict = field(default_factory=dict)  # {역할 id: {"name": 보일 이름, "scope": [허용 범위]}}
    login: dict = field(default_factory=dict)  # 로그인해서 토큰 받는 법(서비스마다 다르다)

    def role_name(self, role: str) -> str:
        return self.roles.get(role, {}).get("name", role)

    def role_scope(self, role: str) -> list:
        """그 역할의 범위. 역할을 안 골랐거나 범위를 안 적었으면 프로젝트 범위."""
        return self.roles.get(role, {}).get("scope") or self.scope

    def is_practice(self, role: str) -> bool:
        """우리가 띄운 연습용 가짜 서버인가. 점검 대상이 아니다."""
        return bool(self.roles.get(role, {}).get("practice"))


def _norm_roles(roles):
    """역할은 이름만 주어도 되고, 범위까지 주어도 된다.

    practice 는 '점검 대상이 아니라 우리가 띄운 연습용 서버' 라는 표시다.
    login 은 그 역할만 로그인 모양이 다를 때 쓴다(관리자 API 는 사용자 API 와 다른 앱이다).
    **여기 안 적은 열쇠는 조용히 버려진다** — 팩에 써 놓고도 안 먹는다.
    """
    out = {}
    for rid, value in (roles or {}).items():
        if isinstance(value, str):
            out[rid] = {"name": value, "scope": None, "practice": False, "login": None}
        elif isinstance(value, dict) and value.get("name"):
            out[rid] = {"name": value["name"], "scope": value.get("scope"),
                        "practice": bool(value.get("practice")),
                        "login": value.get("login") or None}
        else:
            raise ValueError(f"역할 {rid} 은 이름 문자열이거나 name 을 가진 dict 여야 합니다")
    return out


def group_targets(targets, projects: dict) -> list:
    """화면에 보일 대상 묶음. **점검 대상이 먼저, 연습용은 따로 뒤에.**

    전에는 프로젝트 하나로만 묶어서, 연습용 가짜 서버가 실서버 두 개와 같은
    '새싹에듀 모의해킹' 묶음 안에 들어가 있었다. 묶음 이름이 같으면 고를 때도
    보여 줄 때도 점검 범위처럼 읽힌다 — 이름으로 못박고 자리를 떼어 놓는다.
    """
    seen, out = {}, []
    for t in targets:
        pid = t["project"]
        pj = projects.get(pid)
        practice = bool(pj and pj.is_practice(t["role"]))
        key = ("1" if practice else "0", pid)
        if key not in seen:
            name = pj.name if pj else f"{pid} (팩 없음)"
            seen[key] = {"label": PRACTICE_LABEL if practice else name,
                         "practice": practice, "targets": []}
            out.append((key, seen[key]))
        seen[key]["targets"].append(t)
    return [g for _key, g in sorted(out, key=lambda kv: kv[0])]


from dashboard import cvss as cvss_mod
from dashboard import needs as needs_mod


def _check_vuln(value: str) -> str:
    """META 의 취약점 유형이 팀 어휘인지 본다. 새 말을 만들면 모듈이 안 올라간다 —
    어휘가 갈라지면 노션 취약점 항목과 묶이지 않는다."""
    from dashboard.grouping import VULN_TYPES
    if not value:
        return "기타"
    if value not in VULN_TYPES:
        raise ValueError(f"vuln 은 {' · '.join(VULN_TYPES)} 중 하나여야 합니다 (받은 값: {value})")
    return value


def _check_cvss(vector: str) -> str:
    """META 에 적은 CVSS 벡터가 말이 되는지 등록할 때 본다. 틀리면 모듈이 안 올라간다."""
    if not vector:
        return ""
    cvss_mod.parse(vector)          # 틀리면 BadVector(ValueError) 가 올라가 오류로 보인다
    return vector


def _validate(meta: dict) -> None:
    missing = [k for k in REQUIRED if k not in meta]
    if missing:
        raise ValueError(f"META 에 {', '.join(missing)} 가 없습니다")
    if meta["kind"] not in KINDS:
        raise ValueError(f"kind 는 {KINDS} 중 하나여야 합니다")
    if meta.get("stage", "check") not in STAGES:
        raise ValueError(f"stage 는 {STAGES} 중 하나여야 합니다")
    if meta.get("severity", "medium") not in SEVERITIES:
        raise ValueError(f"severity 는 {SEVERITIES} 중 하나여야 합니다")
    for a in meta["attack"]:
        if a.get("tactic") not in TACTIC_ORDER or not a.get("technique"):
            raise ValueError(f"attack 항목이 잘못됐습니다: {a}")


def discover(package_name: str = "modules", project: str = ""):
    """(모듈 dict, 불러오기 오류 list) 를 돌려준다. 모듈 하나가 깨져도 나머지는 뜬다."""
    package = importlib.import_module(package_name)
    found, errors = {}, []
    for info in pkgutil.iter_modules(package.__path__):
        if info.name.startswith("_"):
            continue
        source = f"{package_name.replace('.', '/')}/{info.name}.py"
        try:
            mod = importlib.import_module(f"{package_name}.{info.name}")
            meta = getattr(mod, "META", None)
            if not isinstance(meta, dict) or not callable(getattr(mod, "run", None)):
                raise ValueError("META(dict) 와 run() 이 필요합니다")
            _validate(meta)
            if meta["id"] in found:
                raise ValueError(f"id 중복: {meta['id']}")
            found[meta["id"]] = ModuleInfo(
                id=meta["id"], name=meta["name"], category=meta["category"],
                kind=meta["kind"], attack=meta["attack"], description=meta["description"],
                params=meta.get("params", []), run=mod.run, source=source, project=project,
                stage=meta.get("stage", "check"), severity=meta.get("severity", "medium"),
                roles=meta.get("roles", []), needs=needs_mod.validate(meta.get("needs")),
                cvss=_check_cvss(meta.get("cvss", "")), vuln=_check_vuln(meta.get("vuln", "")),
            )
        except Exception as e:  # noqa: BLE001 — 깨진 모듈은 화면에 오류로 보여 준다
            errors.append((source, str(e)))
    return found, errors


def discover_projects(package_name: str = "projects"):
    """(프로젝트 dict, [(프로젝트 id, 모듈 dict)], 오류 list)."""
    package = importlib.import_module(package_name)
    projects, packs, errors = {}, [], []
    for info in pkgutil.iter_modules(package.__path__):
        if info.name.startswith("_") or not info.ispkg:
            continue
        pid, source = info.name, f"{package_name}/{info.name}/"
        try:
            if pid == GENERAL:
                raise ValueError(f"'{GENERAL}' 는 예약된 이름입니다")
            meta = getattr(importlib.import_module(f"{package_name}.{pid}"), "PROJECT", None)
            if not isinstance(meta, dict) or not meta.get("name") or not meta.get("scope"):
                raise ValueError("PROJECT(dict) 에 name·scope 가 필요합니다")
            projects[pid] = ProjectInfo(id=pid, name=meta["name"], scope=[h.lower() for h in meta["scope"]],
                                        description=meta.get("description", ""), source=source,
                                        roles=_norm_roles(meta.get("roles", {})),
                                        login=meta.get("login") or {})
        except Exception as e:  # noqa: BLE001
            errors.append((source, str(e)))
            continue
        if importlib.util.find_spec(f"{package_name}.{pid}.modules"):
            found, errs = discover(f"{package_name}.{pid}.modules", project=pid)
            packs.append((pid, found))
            errors += errs
    return projects, packs, errors


def load_catalog(general_scope, modules_pkg: str = "modules", projects_pkg: str = "projects"):
    """범용 모듈 + 모든 프로젝트 팩을 읽는다. 모듈 id 는 전체에서 하나여야 한다."""
    projects = {GENERAL: ProjectInfo(GENERAL, "범용", list(general_scope), "특정 프로젝트에 묶이지 않은 대상")}
    modules, errors = discover(modules_pkg)
    found_projects, packs, p_errors = discover_projects(projects_pkg)
    projects.update(found_projects)
    errors += p_errors
    for _pid, found in packs:
        for mid, m in found.items():
            if mid in modules:
                errors.append((m.source, f"id 중복: {mid} ({modules[mid].source} 와 겹침)"))
                continue
            modules[mid] = m
    ordered = dict(sorted(modules.items(), key=lambda kv: (kv[1].first_tactic_order, kv[1].name)))
    return projects, ordered, errors


def modules_for(modules: dict, project_id: str, role: str = "") -> dict:
    """이 대상에 쓸 수 있는 모듈.

    범용 + 그 프로젝트 전용 중에서, 모듈이 역할을 정해 두었으면
    대상의 역할과 맞는 것만. 대상에 역할을 안 골랐으면 가리지 않는다.
    """
    return {k: m for k, m in modules.items()
            if m.project in ("", project_id) and (not m.roles or not role or role in m.roles)}
