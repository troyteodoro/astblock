"""Rewrite blocked statements and compile the result."""

from __future__ import annotations

import ast
import logging
from types import CodeType
from typing import Mapping

from ._blocklist import Blocklist, Rule
from ._errors import StaleRuleError
from ._fingerprint import find_statements

logger = logging.getLogger("astblock")

_NEW_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _contains_yield(node: ast.AST) -> bool:
    """True if ``node`` yields on behalf of its enclosing function."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.Yield, ast.YieldFrom)):
            return True
        if not isinstance(child, _NEW_SCOPES) and _contains_yield(child):
            return True
    return False


def _replacement(node: ast.stmt, rule: Rule) -> ast.stmt:
    call = (
        "__import__('astblock._runtime', fromlist=['blocked']).blocked("
        f"{rule.fingerprint!r}, {rule.action!r}, {rule.reason!r})"
    )
    if _contains_yield(node) and not isinstance(node, _NEW_SCOPES):
        # Removing a function's only ``yield`` would silently turn a generator
        # into a plain function. Keep an unreachable yield so it stays one.
        source = f"if False:\n    yield\nelse:\n    {call}"
    else:
        source = call
    new = ast.parse(source).body[0]
    for child in ast.walk(new):
        ast.copy_location(child, node)
    return new


def apply_rules(tree: ast.Module, module: str, rules: Mapping[str, Rule]) -> set[str]:
    """Replace blocked statements in ``tree`` in place.

    Returns the fingerprints that matched a statement.
    """
    matched: set[str] = set()
    for statement in find_statements(tree, module):
        rule = rules.get(statement.fingerprint)
        if rule is None:
            continue
        matched.add(statement.fingerprint)
        statement.block[statement.index] = _replacement(statement.node, rule)
    return matched


def compile_with_blocklist(
    source: str | bytes, filename: str, module: str, blocklist: Blocklist
) -> CodeType:
    """Compile ``source`` as ``module`` with the blocklist's rules applied."""
    tree = ast.parse(source, filename=filename)
    rules = blocklist.rules_for(module)
    if rules:
        matched = apply_rules(tree, module, rules)
        if matched:
            logger.warning("astblock: blocked %d statement(s) in %s: %s",
                           len(matched), module, ", ".join(sorted(matched)))
        stale = sorted(set(rules) - matched)
        if stale:
            # A stale rule means a statement someone asked to block is about to
            # run. Under a strict blocklist that is fatal, on the same reasoning
            # that a missing blocklist file is: running unpatched after an
            # emergency patch was requested is worse than failing to start.
            if blocklist.strict:
                raise StaleRuleError(module, stale)
            logger.warning(
                "astblock: %d rule(s) for %s matched nothing (code changed since the "
                "rule was written?): %s", len(stale), module, ", ".join(stale))
    return compile(tree, filename, "exec", dont_inherit=True)
