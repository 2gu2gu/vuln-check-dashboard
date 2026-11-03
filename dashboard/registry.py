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
STAGES = ("collect", "check", "probe")
STAGE_LABEL = {"collect": "표면 수집", "check": "대상 점검", "probe": "지점 점검"}
GENERAL = "general"  # 어느 프로젝트에도 속하지 않는 대상


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
    stage: str = "check"
    severity: str = "medium"  # probe 가 '취약'을 낼 때 기본 심각도

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
                                        description=meta.get("description", ""), source=source)
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


def modules_for(modules: dict, project_id: str) -> dict:
    """그 프로젝트 대상에 쓸 수 있는 모듈 = 범용 + 그 프로젝트 전용."""
    return {k: m for k, m in modules.items() if m.project in ("", project_id)}
