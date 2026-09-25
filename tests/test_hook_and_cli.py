import importlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import astblock
from astblock import Blocklist, Rule

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

MODULE_SOURCE = textwrap.dedent("""
    def charge():
        steps = ["validate"]
        steps.append("send_duplicate_email")
        steps.append("charge_card")
        return steps
""")


@pytest.fixture
def app(tmp_path, monkeypatch):
    """A temporary package ``demoapp`` with module ``demoapp.billing``."""
    package = tmp_path / "demoapp"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "billing.py").write_text(MODULE_SOURCE)
    monkeypatch.syspath_prepend(str(tmp_path))
    yield tmp_path
    astblock.uninstall()
    for name in [n for n in sys.modules if n == "demoapp" or n.startswith("demoapp.")]:
        del sys.modules[name]
    importlib.invalidate_caches()


def email_rule(action="skip"):
    fingerprint = next(s.fingerprint for s in astblock.fingerprint_source(MODULE_SOURCE, "demoapp.billing")
                       if s.lineno == 4)
    return Rule("demoapp.billing", fingerprint, action=action, reason="INC-42")


def test_hook_patches_targeted_module(app):
    astblock.install(Blocklist([email_rule()]))
    billing = importlib.import_module("demoapp.billing")
    assert billing.charge() == ["validate", "charge_card"]


def test_stale_pyc_cannot_bypass_the_hook(app):
    importlib.import_module("demoapp.billing")          # writes an unpatched .pyc
    assert list((app / "demoapp" / "__pycache__").glob("billing*.pyc"))
    del sys.modules["demoapp.billing"]
    astblock.install(Blocklist([email_rule()]))
    billing = importlib.import_module("demoapp.billing")
    assert billing.charge() == ["validate", "charge_card"]


def test_uninstall_restores_normal_imports(app):
    astblock.install(Blocklist([email_rule()]))
    astblock.uninstall()
    billing = importlib.import_module("demoapp.billing")
    assert "send_duplicate_email" in billing.charge()


def test_already_imported_module_is_warned_about(app, caplog):
    importlib.import_module("demoapp.billing")
    astblock.install(Blocklist([email_rule()]))
    assert "already imported" in caplog.text


def test_install_from_env(app, tmp_path, monkeypatch):
    path = tmp_path / "blocklist.json"
    path.write_text(json.dumps(Blocklist([email_rule()]).to_dict()))
    monkeypatch.setenv("ASTBLOCK_FILE", str(path))
    assert astblock.install_from_env() is not None
    assert importlib.import_module("demoapp.billing").charge() == ["validate", "charge_card"]


# -- CLI (run in subprocesses, as a user would) ---------------------------

def cli(*args, cwd, extra_path):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(SRC_DIR), str(extra_path)]))
    return subprocess.run([sys.executable, "-m", "astblock", *args], cwd=cwd, env=env,
                          capture_output=True, text=True)


def test_cli_list_and_check(app):
    rule = email_rule()
    listing = cli("list", "demoapp.billing", cwd=app, extra_path=app)
    assert rule.fingerprint in listing.stdout

    path = app / "blocklist.json"
    path.write_text(json.dumps(Blocklist([rule]).to_dict()))
    ok = cli("check", str(path), cwd=app, extra_path=app)
    assert ok.returncode == 0 and "OK" in ok.stdout

    (app / "demoapp" / "billing.py").write_text(MODULE_SOURCE.replace("duplicate", "dup"))
    stale = cli("check", str(path), cwd=app, extra_path=app)
    assert stale.returncode == 1 and "STALE" in stale.stdout


def test_cli_run_script_and_module(app):
    script = app / "main.py"
    script.write_text("from demoapp.billing import charge\nprint(charge())\nprint('end')\n")
    main_rule = next(s for s in astblock.fingerprint_source(script.read_text(), "__main__")
                     if s.lineno == 3)
    path = app / "blocklist.json"
    path.write_text(json.dumps(Blocklist([
        email_rule(),
        Rule("__main__", main_rule.fingerprint, action="skip"),
    ]).to_dict()))

    result = cli("run", "--blocklist", str(path), str(script), cwd=app, extra_path=app)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "['validate', 'charge_card']"

    (app / "demoapp" / "__main__.py").write_text(
        "from demoapp.billing import charge\nprint(charge())\n")
    result = cli("run", "--blocklist", str(path), "-m", "demoapp", cwd=app, extra_path=app)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "['validate', 'charge_card']"
