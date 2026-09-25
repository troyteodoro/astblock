"""Import hook that compiles targeted modules with the blocklist applied.

Only modules named in the blocklist are intercepted; everything else imports
exactly as normal. Targeted modules are always compiled from source and their
bytecode is never cached, so a stale ``.pyc`` can't bypass a rule and a
patched ``.pyc`` never outlives the blocklist.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import logging
import os
import sys
from types import CodeType

from ._blocklist import Blocklist
from ._transform import compile_with_blocklist

logger = logging.getLogger("astblock")

ENV_VAR = "ASTBLOCK_FILE"

_finder: "_BlockingFinder | None" = None


class _BlockingLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, fullname: str, path: str, blocklist: Blocklist) -> None:
        super().__init__(fullname, path)
        self._blocklist = blocklist

    def get_code(self, fullname: str) -> CodeType:
        source = self.get_data(self.path)
        return compile_with_blocklist(source, self.path, fullname, self._blocklist)


class _BlockingFinder(importlib.abc.MetaPathFinder):
    # Recognised across module identities: if astblock is imported twice (a
    # vendored copy alongside an installed one) the two _BlockingFinder
    # classes are different objects, so isinstance would not see the other
    # one. An attribute name is the same in both.
    _astblock_finder = True

    def __init__(self, blocklist: Blocklist) -> None:
        self.blocklist = blocklist

    def find_spec(self, fullname, path, target=None):
        if fullname not in self.blocklist.modules:
            return None
        spec = None
        for finder in sys.meta_path:
            # Skip every blocking finder, not just this one: two of them on
            # sys.meta_path would otherwise call into each other until the
            # stack ran out.
            if getattr(finder, "_astblock_finder", False) or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(fullname, path, target)
            if spec is not None:
                break
        if spec is None:
            return None
        loader = spec.loader
        if isinstance(loader, importlib.machinery.SourceFileLoader) and not isinstance(
            loader, _BlockingLoader
        ):
            spec.loader = _BlockingLoader(fullname, loader.path, self.blocklist)
        else:
            logger.warning(
                "astblock: cannot apply rules to %s: it is not loaded from a .py "
                "source file (loader: %r)", fullname, loader)
        return spec


def install(blocklist: Blocklist | str | os.PathLike[str]) -> Blocklist:
    """Start applying ``blocklist`` to modules imported from now on.

    Accepts a Blocklist or a path to a blocklist JSON file. Replaces any
    previously installed blocklist. Returns the installed Blocklist.
    """
    global _finder
    if not isinstance(blocklist, Blocklist):
        blocklist = Blocklist.load(blocklist)
    uninstall()
    already = sorted(name for name in blocklist.modules if name in sys.modules)
    if already:
        logger.warning(
            "astblock: already imported, rules won't apply to these until the "
            "process restarts: %s", ", ".join(already))
    _finder = _BlockingFinder(blocklist)
    sys.meta_path.insert(0, _finder)
    return blocklist


def uninstall() -> None:
    """Stop intercepting imports. Modules already imported stay patched."""
    global _finder
    if _finder is not None:
        try:
            sys.meta_path.remove(_finder)
        except ValueError:
            pass
        _finder = None


def is_installed() -> bool:
    return _finder is not None and _finder in sys.meta_path


def install_from_env(var: str = ENV_VAR) -> Blocklist | None:
    """Install the blocklist named by ``$ASTBLOCK_FILE``, if set.

    A blocklist that is set but unreadable or invalid raises BlocklistError
    rather than being ignored: running unpatched when an emergency patch was
    requested is worse than failing to start.
    """
    path = os.environ.get(var)
    if not path:
        return None
    return install(path)
