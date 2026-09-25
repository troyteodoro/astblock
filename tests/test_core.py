import textwrap

import pytest

import astblock
from astblock import Blocklist, BlockedStatementError, BlocklistError, Rule


def fps(source, module="m"):
    return [s.fingerprint for s in astblock.fingerprint_source(textwrap.dedent(source), module)]


def fp_at(source, lineno, module="m"):
    for s in astblock.fingerprint_source(textwrap.dedent(source), module):
        if s.lineno == lineno:
            return s.fingerprint
    raise AssertionError(f"no statement on line {lineno}")


def run(source, rules, module="m"):
    blocklist = Blocklist(rules)
    code = astblock.compile_with_blocklist(textwrap.dedent(source), "<test>", module, blocklist)
    namespace = {}
    exec(code, namespace)
    return namespace


# -- fingerprints --------------------------------------------------------

def test_fingerprint_ignores_formatting_comments_and_line_shifts():
    a = "def f():\n    x = compute(1, 2)\n"
    b = "# a comment\n\n\ndef f():\n    # explain\n    x = compute( 1,2 )  # trailing\n"
    assert fps(a) == fps(b)


def test_fingerprint_changes_when_code_changes():
    assert fps("x = compute(1, 2)") != fps("x = compute(1, 3)")


def test_fingerprint_depends_on_module_and_scope():
    src = "def f():\n    go()\ndef g():\n    go()\n"
    first_in_f, first_in_g = fp_at(src, 2), fp_at(src, 4)
    assert first_in_f != first_in_g
    assert fp_at(src, 2, module="other") != first_in_f


def test_identical_statements_in_one_scope_are_distinct():
    src = "go()\ngo()\n"
    assert len(set(fps(src))) == 2


def test_compiler_directives_are_not_blockable():
    src = """
    from __future__ import annotations
    def f():
        global X
        X = 1
    """
    kinds = [type(s.node).__name__ for s in astblock.fingerprint_source(textwrap.dedent(src), "m")]
    assert kinds == ["FunctionDef", "Assign"]


def test_nested_blocks_are_found():
    src = """
    try:
        a()
    except ValueError:
        b()
    finally:
        c()
    match x:
        case 1:
            d()
    """
    names = {s.node.value.func.id for s in astblock.fingerprint_source(textwrap.dedent(src), "m")
             if hasattr(s.node, "value") and hasattr(s.node.value, "func")}
    assert names == {"a", "b", "c", "d"}


# -- rewriting -----------------------------------------------------------

SRC = """
log = []
def work():
    log.append("before")
    log.append("dangerous")
    log.append("after")
    return log
"""


def test_skip_removes_only_the_blocked_statement():
    rule = Rule("m", fp_at(SRC, 5), action="skip")
    ns = run(SRC, [rule])
    assert ns["work"]() == ["before", "after"]


def test_raise_stops_at_the_blocked_statement():
    rule = Rule("m", fp_at(SRC, 5), action="raise", reason="INC-1")
    ns = run(SRC, [rule])
    with pytest.raises(BlockedStatementError, match="INC-1"):
        ns["work"]()
    assert ns["log"] == ["before"]


def test_rules_for_other_modules_do_not_apply():
    rule = Rule("other", fp_at(SRC, 5, module="other"), action="skip")
    ns = run(SRC, [rule])
    assert ns["work"]() == ["before", "dangerous", "after"]


def test_hits_are_counted():
    astblock.reset_hits()
    fingerprint = fp_at(SRC, 5)
    ns = run(SRC, [Rule("m", fingerprint, action="skip")])
    ns["work"]()
    ns["work"]()
    assert astblock.hits()[fingerprint] == 2


def test_blocking_only_yield_keeps_function_a_generator():
    src = "def gen():\n    yield 1\n"
    ns = run(src, [Rule("m", fp_at(src, 2), action="skip")])
    assert list(ns["gen"]()) == []


def test_stale_rule_is_reported(caplog):
    run(SRC, [Rule("m", "0" * 16, action="skip")])
    assert "matched nothing" in caplog.text


# -- blocklist format ----------------------------------------------------

def test_blocklist_round_trip():
    bl = Blocklist([Rule("m", "a" * 16, "skip", "why")])
    again = Blocklist.from_dict(bl.to_dict())
    assert list(again) == list(bl)


@pytest.mark.parametrize("rule", [
    {"module": "m", "fingerprint": "xyz"},
    {"module": "m", "fingerprint": "a" * 16, "action": "delete"},
    {"module": "m", "fingerprint": "a" * 16, "acton": "skip"},
    {"fingerprint": "a" * 16},
])
def test_invalid_rules_are_rejected(rule):
    with pytest.raises(BlocklistError):
        Blocklist.from_dict({"version": 1, "rules": [rule]})
