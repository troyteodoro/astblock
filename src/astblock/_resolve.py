"""Locate modules and verify rules without importing anything.

``importlib.util.find_spec`` imports the parent packages of a dotted name,
which runs their ``__init__.py``. Everything here has to work on a blocklist
that is not yet trusted, so it uses ``PathFinder``, which locates modules
without executing them.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
from dataclasses import dataclass

from ._fingerprint import Statement, fingerprint_source


@dataclass(frozen=True)
class Result:
    """The outcome of checking one rule against the code on disk."""

    status: str  # "ok", "stale", "missing" or "skipped"
    module: str
    fingerprint: str | None = None
    detail: str = ""
    statement: Statement | None = None
    path: str | None = None

    @property
    def is_problem(self) -> bool:
        return self.status in ("stale", "missing")


def find_spec_without_importing(name: str):
    """Locate ``name`` on sys.path without importing it or its parents."""
    parts = name.split(".")
    search_path = None  # None means "use sys.path"
    spec = None
    for position, _ in enumerate(parts):
        dotted = ".".join(parts[: position + 1])
        spec = importlib.machinery.PathFinder.find_spec(dotted, search_path)
        if spec is None:
            return None
        if position < len(parts) - 1:
            locations = spec.submodule_search_locations
            if not locations:
                return None  # a parent component is a module, not a package
            search_path = list(locations)
    return spec


def source_path_for(name: str, allow_import: bool = False) -> str:
    """Return the ``.py`` source path for module ``name``.

    ``allow_import`` falls back to ``importlib.util.find_spec`` for layouts
    only a meta path finder can resolve, such as a strict editable install.
    That import runs the parent packages, so it is opt-in.
    """
    spec = find_spec_without_importing(name)
    if spec is None and allow_import:
        spec = importlib.util.find_spec(name)
    if spec is None or not spec.origin or not spec.origin.endswith(".py"):
        raise LookupError(
            f"cannot find Python source for module {name!r} without importing it"
        )
    return spec.origin


def verify(blocklist, allow_import: bool = False) -> list[Result]:
    """Check every rule against the source it names, without importing it.

    Rules for ``__main__`` are skipped: a script's module name says nothing
    about where the file is. They are still checked when the script itself is
    compiled.
    """
    results: list[Result] = []
    for module in sorted(blocklist.modules):
        rules = blocklist.rules_for(module)
        if module == "__main__":
            results.append(Result("skipped", module,
                                  detail="rules for scripts can't be checked by module name"))
            continue
        try:
            path = source_path_for(module, allow_import)
            with open(path, "rb") as handle:
                source = handle.read()
            found = {s.fingerprint: s for s in fingerprint_source(source, module, path)}
        except (LookupError, ImportError, OSError, SyntaxError) as exc:
            results.append(Result("missing", module, detail=str(exc)))
            continue
        for fingerprint in sorted(rules):
            statement = found.get(fingerprint)
            if statement is None:
                results.append(Result("stale", module, fingerprint,
                                      detail="matches no statement", path=path))
            else:
                results.append(Result("ok", module, fingerprint,
                                      statement=statement, path=path))
    return results
