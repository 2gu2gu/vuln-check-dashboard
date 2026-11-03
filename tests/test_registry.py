import sys
import textwrap

from dashboard.registry import GENERAL, load_catalog, modules_for

GOOD = '''
from dashboard.core import Finding
META = {"id": "%s", "name": "n", "category": "c", "kind": "passive",
        "attack": [{"tactic": "TA0043", "technique": "T1595"}], "description": "d"}
def run(target, params):
    return []
'''


def _pkg(root, name, files):
    d = root / name
    d.mkdir(parents=True)
    (d / "__init__.py").write_text(files.pop("__init__.py", ""), encoding="utf-8")
    for fname, body in files.items():
        (d / fname).write_text(textwrap.dedent(body), encoding="utf-8")
    return d


def test_real_catalog_loads():
    projects, modules, errors = load_catalog(["localhost"])
    assert errors == []
    assert {"http_security_headers", "tech_fingerprint", "sesacedu_exposed_paths",
            "surface_crawl", "surface_import", "reflection_check"} <= set(modules)
    assert modules["surface_crawl"].stage == "collect" and modules["reflection_check"].stage == "probe"
    assert modules["http_security_headers"].stage == "check"
    assert "sesacedu" in projects and GENERAL in projects
    assert modules["sesacedu_exposed_paths"].project == "sesacedu"
    assert "robots_txt" not in modules  # _template.py 는 건너뜀


def test_project_modules_hidden_from_other_projects():
    _, modules, _ = load_catalog(["localhost"])
    assert "sesacedu_exposed_paths" not in modules_for(modules, GENERAL)
    assert "sesacedu_exposed_paths" in modules_for(modules, "sesacedu")
    assert "http_security_headers" in modules_for(modules, "sesacedu")


def test_broken_and_duplicate_modules_are_reported(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(tmp_path))
    _pkg(tmp_path, "tmods", {"ok.py": GOOD % "dup", "broken.py": "raise RuntimeError('boom')",
                             "nometa.py": "def run(t, p): return []"})
    projects_dir = _pkg(tmp_path, "tprojs", {})
    _pkg(projects_dir, "alpha", {"__init__.py": "PROJECT = {'name': 'A', 'scope': ['a.test']}"})
    _pkg(projects_dir / "alpha", "modules", {"same.py": GOOD % "dup", "own.py": GOOD % "alpha_only"})
    _pkg(projects_dir, "noscope", {"__init__.py": "PROJECT = {'name': 'B'}"})
    try:
        projects, modules, errors = load_catalog(["localhost"], "tmods", "tprojs")
    finally:
        for k in [k for k in sys.modules if k.startswith(("tmods", "tprojs"))]:
            del sys.modules[k]
    assert set(modules) == {"dup", "alpha_only"}
    assert modules["dup"].project == ""  # 범용이 먼저 차지
    assert set(projects) == {GENERAL, "alpha"}
    joined = " ".join(src + msg for src, msg in errors)
    assert "broken.py" in joined and "nometa.py" in joined and "id 중복" in joined and "noscope" in joined
