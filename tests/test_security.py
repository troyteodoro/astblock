"""Regressions for the hardening in 0.2.0.

Each test here corresponds to a specific way the tool could be made to run
code, hide what it did, or fail open.
"""

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import astblock
from astblock import Blocklist, BlocklistError, Rule, StaleRuleError

SRC_DIR = Path(__file__).resolve().parents[1] / "src"


def write(path: Path, text: str) -> Path:
    path.write_text(textwrap.dedent(text))
    return path


def cli(*args, cwd, extra_path):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(SRC_DIR), str(extra_path)]))
    return subprocess.run([sys.executable, "-m", "astblock", *args], cwd=cwd, env=env,
                          capture_output=True, text=True)


# -- reading a blocklist must not execute the code it names ---------------

@pytest.fixture
def package_with_side_effect(tmp_path):
    """A package whose __init__.py writes a file when it is executed."""
    package = tmp_path / "loud"
    package.mkdir()
    write(package / "__init__.py", f"""
        from pathlib import Path
        Path({str(tmp_path / 'EXECUTED')!r}).write_text('ran')
    """)
    write(package / "billing.py", "def charge():\n    return 1\n")
    return tmp_path


def test_check_does_not_import_the_modules_it_names(package_with_side_effect):
    tmp_path = package_with_side_effect
    blocklist = write(tmp_path / "bl.json", json.dumps(
        {"version": 1, "rules": [{"module": "loud.billing", "fingerprint": "a" * 16}]}))
    result = cli("check", str(blocklist), cwd=tmp_path, extra_path=tmp_path)
    assert not (tmp_path / "EXECUTED").exists(), "__init__.py ran while checking a blocklist"
    assert "loud.billing" in result.stdout


def test_list_does_not_import_the_module_it_reads(package_with_side_effect):
    tmp_path = package_with_side_effect
    result = cli("list", "loud.billing", cwd=tmp_path, extra_path=tmp_path)
    assert not (tmp_path / "EXECUTED").exists(), "__init__.py ran while listing statements"
    assert result.returncode == 0 and "charge" in result.stdout


def test_allow_import_does_not_import_when_it_does_not_have_to(package_with_side_effect):
    """--allow-import is a fallback, not a switch that forces importing.

    A package that PathFinder can resolve is resolved that way even with the
    flag set, so the escape hatch costs nothing on ordinary layouts.
    """
    tmp_path = package_with_side_effect
    result = cli("list", "loud.billing", "--allow-import", cwd=tmp_path, extra_path=tmp_path)
    assert result.returncode == 0 and "charge" in result.stdout
    assert not (tmp_path / "EXECUTED").exists()


def test_module_only_a_meta_path_finder_can_resolve_needs_allow_import(tmp_path):
    """Stand in for a strict editable install: importable, but not on sys.path."""
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    write(hidden / "ghost.py", "def work():\n    return 1\n")
    finder = write(tmp_path / "sitecustomize.py", f"""
        import importlib.machinery, importlib.abc, sys

        class Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path, target=None):
                if fullname != "ghost":
                    return None
                origin = {str(hidden / 'ghost.py')!r}
                return importlib.util.spec_from_file_location(fullname, origin)

        import importlib.util
        sys.meta_path.insert(0, Finder())
    """)
    without = cli("list", "ghost", cwd=tmp_path, extra_path=tmp_path)
    assert without.returncode == 2 and "without importing it" in without.stderr

    with_flag = cli("list", "ghost", "--allow-import", cwd=tmp_path, extra_path=tmp_path)
    assert with_flag.returncode == 0 and "work" in with_flag.stdout


# -- a reason cannot forge log lines --------------------------------------

@pytest.mark.parametrize("reason", [
    "outage\nWARNING astblock: all clear, nothing blocked",
    "outage\rall clear",
    "esc\x1b[2Kall clear",
    "sep all clear",
    "nul\x00",
])
def test_reason_with_control_characters_is_rejected(reason):
    with pytest.raises(BlocklistError, match="control character"):
        Rule("m", "a" * 16, "skip", reason)


def test_reason_length_is_capped():
    Rule("m", "a" * 16, "skip", "x" * 200)
    with pytest.raises(BlocklistError, match="at most 200 characters"):
        Rule("m", "a" * 16, "skip", "x" * 201)


# -- a blocklist cannot be unbounded --------------------------------------

def test_rule_count_is_capped():
    rules = [{"module": "m", "fingerprint": f"{i:016x}"} for i in range(10_001)]
    with pytest.raises(BlocklistError, match="more than the 10000 allowed"):
        Blocklist.from_dict({"version": 1, "rules": rules})


def test_oversized_file_is_rejected(tmp_path):
    path = tmp_path / "big.json"
    path.write_text(" " * (1 << 20) + "{}")
    with pytest.raises(BlocklistError, match="byte limit"):
        Blocklist.load(path)


# -- file permissions are part of the boundary ----------------------------

@pytest.mark.skipif(os.name != "posix", reason="mode bits are only meaningful on POSIX")
def test_world_writable_blocklist_is_refused(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text(json.dumps({"version": 1, "rules": []}))
    os.chmod(path, 0o666)
    with pytest.raises(BlocklistError, match="world-writable"):
        Blocklist.load(path)
    os.chmod(path, 0o644)
    assert len(Blocklist.load(path)) == 0


@pytest.mark.skipif(os.name != "posix", reason="mode bits are only meaningful on POSIX")
def test_group_writable_blocklist_warns_but_loads(tmp_path, caplog):
    path = tmp_path / "bl.json"
    path.write_text(json.dumps({"version": 1, "rules": []}))
    os.chmod(path, 0o664)
    assert len(Blocklist.load(path)) == 0
    assert "group-writable" in caplog.text


# -- a strict blocklist fails closed on a stale rule ----------------------

SRC = "def work():\n    danger()\n    return 1\n"


def test_strict_blocklist_raises_when_a_rule_matches_nothing():
    blocklist = Blocklist([Rule("m", "0" * 16, "skip")], strict=True)
    with pytest.raises(StaleRuleError) as caught:
        astblock.compile_with_blocklist(SRC, "<t>", "m", blocklist)
    assert caught.value.module == "m"
    assert caught.value.fingerprints == ["0" * 16]


def test_non_strict_blocklist_still_only_warns(caplog):
    blocklist = Blocklist([Rule("m", "0" * 16, "skip")])
    astblock.compile_with_blocklist(SRC, "<t>", "m", blocklist)
    assert "matched nothing" in caplog.text


def test_strict_survives_a_json_round_trip():
    original = Blocklist([Rule("m", "a" * 16, "skip")], strict=True)
    again = Blocklist.from_json(json.dumps(original.to_dict()))
    assert again.strict is True
    assert Blocklist.from_dict({"version": 1, "rules": []}).strict is False


def test_strict_must_be_a_boolean():
    with pytest.raises(BlocklistError, match="'strict' must be true or false"):
        Blocklist.from_dict({"version": 1, "strict": "yes", "rules": []})


# -- duplicate finders must not recurse -----------------------------------

def test_two_blocking_finders_do_not_recurse(tmp_path, monkeypatch):
    from astblock._hook import _BlockingFinder

    write(tmp_path / "victim.py", "VALUE = 1\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    blocklist = Blocklist([Rule("victim", "a" * 16, "skip")])
    first, second = _BlockingFinder(blocklist), _BlockingFinder(blocklist)
    monkeypatch.setattr(sys, "meta_path", [second, first, *sys.meta_path])
    sys.modules.pop("victim", None)
    try:
        import victim
        assert victim.VALUE == 1
    finally:
        sys.modules.pop("victim", None)
