"""Command-line interface.

    python -m astblock list myapp.billing [--line 42]
    python -m astblock check blocklist.json
    python -m astblock run --blocklist blocklist.json -m myapp [args...]
    python -m astblock run --blocklist blocklist.json script.py [args...]
"""

from __future__ import annotations

import argparse
import builtins
import importlib.machinery
import importlib.util
import json
import os
import runpy
import sys
import types

from ._blocklist import ACTIONS, Blocklist
from ._errors import BlocklistError
from ._fingerprint import fingerprint_source
from ._hook import ENV_VAR, install
from ._transform import compile_with_blocklist


def _looks_like_path(target: str) -> bool:
    return target.endswith(".py") or os.sep in target or (os.altsep or os.sep) in target


def _find_spec_without_importing(name: str):
    """Locate ``name`` on sys.path without importing anything.

    ``importlib.util.find_spec`` imports the parent packages of a dotted name,
    which runs their ``__init__.py``. The commands that only read code must not
    do that: ``check`` exists to inspect a blocklist that is not yet trusted,
    and executing code named by that file would defeat the point of checking
    it. PathFinder locates modules without executing them, so walk the dotted
    name one component at a time, carrying each package's search locations
    down to its child.
    """
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


def _locate(target: str, module: str | None, allow_import: bool = False) -> tuple[str, str]:
    """Return (module_name, source_path) for a module name or a file path."""
    if _looks_like_path(target):
        return module or "__main__", target
    spec = _find_spec_without_importing(target)
    if spec is None and allow_import:
        # Opt-in fallback for layouts only a custom meta path finder can
        # resolve, such as a strict editable install. This imports the parent
        # packages of `target`, so only use it on a blocklist you trust.
        spec = importlib.util.find_spec(target)
    if spec is None or not spec.origin or not spec.origin.endswith(".py"):
        raise LookupError(
            f"cannot find Python source for module {target!r} without importing it; "
            f"pass the path to the .py file instead, or --allow-import to let "
            f"astblock import its parent packages"
        )
    return module or target, spec.origin


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _first_line(source_lines: list[str], lineno: int, width: int = 60) -> str:
    text = source_lines[lineno - 1].strip() if 0 < lineno <= len(source_lines) else ""
    return text if len(text) <= width else text[: width - 3] + "..."


def cmd_list(args: argparse.Namespace) -> int:
    module, path = _locate(args.target, args.module, args.allow_import)
    source = _read(path)
    statements = fingerprint_source(source, module, path)
    lines = source.decode("utf-8", errors="replace").splitlines()
    if args.line is not None:
        statements = [s for s in statements if s.lineno == args.line]
    if args.json:
        rules = [{"module": s.module, "fingerprint": s.fingerprint, "action": args.action}
                 for s in statements]
        print(json.dumps({"version": 1, "rules": rules}, indent=2))
        return 0
    print(f"# module: {module}   file: {path}")
    if module == "__main__":
        print("# (pass --module NAME if this file is imported rather than run as a script)")
    for s in statements:
        print(f"{s.lineno:>5}  {s.fingerprint}  {(s.scope or '<module>'):<24}  "
              f"{_first_line(lines, s.lineno)}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    blocklist = Blocklist.load(args.blocklist)
    problems = 0
    for name in sorted(blocklist.modules):
        try:
            module, path = (_locate(name, None, args.allow_import)
                            if name != "__main__" else (None, None))
        except (LookupError, ImportError) as exc:
            print(f"MISSING  {name}: {exc}")
            problems += 1
            continue
        if path is None:
            print(f"SKIP     __main__: rules for scripts can't be checked by module name")
            continue
        source = _read(path)
        lines = source.decode("utf-8", errors="replace").splitlines()
        found = {s.fingerprint: s for s in fingerprint_source(source, module, path)}
        for fingerprint, rule in blocklist.rules_for(name).items():
            statement = found.get(fingerprint)
            if statement is None:
                print(f"STALE    {name} {fingerprint}: matches no statement")
                problems += 1
            else:
                print(f"OK       {name} {fingerprint} [{rule.action}] line "
                      f"{statement.lineno}: {_first_line(lines, statement.lineno)}")
    return 1 if problems else 0


def _run_script(path: str, argv: list[str], blocklist: Blocklist) -> None:
    path = os.path.abspath(path)
    code = compile_with_blocklist(_read(path), path, "__main__", blocklist)
    main = types.ModuleType("__main__")
    main.__file__ = path
    main.__builtins__ = builtins
    sys.modules["__main__"] = main
    sys.argv = [path, *argv]
    sys.path[0] = os.path.dirname(path)
    exec(code, main.__dict__)


def cmd_run(args: argparse.Namespace) -> int:
    source = args.blocklist or os.environ.get(ENV_VAR)
    if not source:
        print(f"astblock run: pass --blocklist or set {ENV_VAR}", file=sys.stderr)
        return 2
    blocklist = install(source)
    rest = list(args.args)
    if args.module:
        if args.script is not None:
            rest.insert(0, args.script)
        sys.argv = [args.module, *rest]
        runpy.run_module(args.module, run_name="__main__", alter_sys=True)
    elif args.script:
        _run_script(args.script, rest, blocklist)
    else:
        print("astblock run: give a script path or -m MODULE", file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m astblock",
                                     description="Block individual statements from running.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="show statements and their fingerprints")
    p_list.add_argument("target", help="module name (myapp.billing) or path to a .py file")
    p_list.add_argument("--module", help="module name to fingerprint a file path as")
    p_list.add_argument("--line", type=int, help="only statements starting on this line")
    p_list.add_argument("--json", action="store_true", help="print as blocklist JSON")
    p_list.add_argument("--action", choices=ACTIONS, default="raise",
                        help="action to use with --json (default: raise)")
    p_list.add_argument("--allow-import", action="store_true",
                        help="allow importing parent packages to resolve the module")
    p_list.set_defaults(func=cmd_list)

    p_check = sub.add_parser("check", help="verify every rule still matches the code")
    p_check.add_argument("blocklist")
    p_check.add_argument("--allow-import", action="store_true",
                         help="allow importing parent packages to resolve modules; "
                              "only use this on a blocklist you trust")
    p_check.set_defaults(func=cmd_check)

    p_run = sub.add_parser("run", help="run a script or module with a blocklist applied")
    p_run.add_argument("--blocklist", help=f"blocklist JSON file (default: ${ENV_VAR})")
    p_run.add_argument("-m", dest="module", help="run a module, like python -m")
    p_run.add_argument("script", nargs="?")
    p_run.add_argument("args", nargs=argparse.REMAINDER)
    p_run.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (BlocklistError, LookupError, OSError, SyntaxError) as exc:
        print(f"astblock: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
