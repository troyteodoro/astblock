"""Stable fingerprints for individual statements.

A fingerprint identifies one statement by *what it is and where it lives*,
not by its line number, so it survives reformatting, comment edits and code
being added above it. It is a hash of:

* the module name (``myapp.billing``),
* the enclosing scope (``Invoice.total`` for a statement inside that method),
* a canonical serialisation of the statement's AST (no positions),
* an occurrence index, so identical statements in the same scope differ.

Any change to the statement itself, or moving it to another function,
produces a different fingerprint. That is deliberate: a blocklist rule
should stop matching when the code it was written against has changed.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Iterator, List

FINGERPRINT_VERSION = "1"
FINGERPRINT_LENGTH = 16

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

# Compiler directives rather than runtime actions; replacing them would change
# how the surrounding code is compiled, so they are never blockable.
_UNBLOCKABLE = (ast.Global, ast.Nonlocal)


@dataclass(frozen=True)
class Statement:
    """One blockable statement found in a module."""

    fingerprint: str
    module: str
    scope: str
    lineno: int
    end_lineno: int | None
    node: ast.stmt = field(compare=False, repr=False)
    block: List[ast.stmt] = field(compare=False, repr=False)
    index: int = field(compare=False, repr=False)


def _canon(value: object) -> str:
    """Serialise an AST without positions, skipping empty/None fields.

    Skipping empty fields keeps fingerprints stable across Python versions
    that add new optional fields (for example ``type_params`` in 3.12).
    """
    if isinstance(value, ast.AST):
        parts = []
        for name in value._fields:
            child = getattr(value, name, None)
            if child is None or (isinstance(child, list) and not child):
                continue
            parts.append(f"{name}={_canon(child)}")
        return f"{type(value).__name__}({','.join(parts)})"
    if isinstance(value, list):
        return "[" + ",".join(_canon(item) for item in value) + "]"
    return f"{type(value).__name__}:{value!r}"


def _hash(module: str, scope: str, canon: str, occurrence: int) -> str:
    payload = "\0".join(
        (f"astblock-v{FINGERPRINT_VERSION}", module, scope, canon, str(occurrence))
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]


def _is_future_import(node: ast.stmt) -> bool:
    return isinstance(node, ast.ImportFrom) and node.module == "__future__"


def _child_blocks(node: ast.AST) -> Iterator[List[ast.stmt]]:
    """Yield every statement list directly inside ``node``.

    Covers ``body``/``orelse``/``finalbody`` and also the bodies of
    ``except`` handlers and ``match`` cases, which are not statements
    themselves but contain statement lists.
    """
    for name in node._fields:
        value = getattr(node, name, None)
        if not isinstance(value, list) or not value:
            continue
        if isinstance(value[0], ast.stmt):
            yield value
            continue
        for item in value:
            body = getattr(item, "body", None)
            if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                yield body


def find_statements(tree: ast.Module, module: str) -> list[Statement]:
    """Return every blockable statement in ``tree``, in source order."""
    found: list[Statement] = []
    seen: dict[tuple[str, str], int] = {}

    def visit(block: List[ast.stmt], scope: list[str]) -> None:
        scope_name = ".".join(scope)
        for index, node in enumerate(block):
            if not isinstance(node, _UNBLOCKABLE) and not _is_future_import(node):
                canon = _canon(node)
                key = (scope_name, canon)
                occurrence = seen.get(key, 0)
                seen[key] = occurrence + 1
                found.append(
                    Statement(
                        fingerprint=_hash(module, scope_name, canon, occurrence),
                        module=module,
                        scope=scope_name,
                        lineno=node.lineno,
                        end_lineno=getattr(node, "end_lineno", None),
                        node=node,
                        block=block,
                        index=index,
                    )
                )
            inner = scope + [node.name] if isinstance(node, _SCOPE_NODES) else scope
            for child in _child_blocks(node):
                visit(child, inner)

    visit(tree.body, [])
    return found


def fingerprint_source(
    source: str | bytes, module: str, filename: str = "<unknown>"
) -> list[Statement]:
    """Parse ``source`` and return its blockable statements."""
    return find_statements(ast.parse(source, filename=filename), module)
