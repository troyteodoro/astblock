"""Blocklist rules and their JSON file format.

Example file::

    {
      "version": 1,
      "strict": true,
      "rules": [
        {
          "module": "myapp.billing",
          "fingerprint": "3f9a0c1d2e4b5a67",
          "action": "skip",
          "reason": "INC-1234: duplicate charge email"
        }
      ]
    }

Whoever can write this file decides which statements in the program run, so
it is loaded defensively: it is size limited, its contents are bounded and
validated, and a world-writable file is refused outright.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from dataclasses import asdict, dataclass
from typing import Iterable, Iterator, Mapping

from ._errors import BlocklistError
from ._fingerprint import FINGERPRINT_LENGTH

logger = logging.getLogger("astblock")

ACTIONS = ("raise", "skip")
FILE_VERSION = 1

#: Bounds on what a blocklist may contain. They exist so that a file nobody
#: has read cannot exhaust memory or flood the logs at startup.
MAX_FILE_BYTES = 1 << 20
MAX_RULES = 10_000
MAX_REASON_LENGTH = 200
MAX_MODULE_LENGTH = 256

_FINGERPRINT_RE = re.compile(rf"^[0-9a-f]{{{FINGERPRINT_LENGTH}}}$")
_RULE_KEYS = {"module", "fingerprint", "action", "reason"}

# A reason is copied into log records, so it must not be able to introduce
# line breaks or terminal escapes: forging a log line in an incident log is
# the whole attack. U+2028/U+2029 are included because some log viewers do
# treat them as line breaks even though Python does not.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")


@dataclass(frozen=True)
class Rule:
    """Block one statement in one module.

    ``action`` is ``"raise"`` (raise BlockedStatementError when reached, the
    default) or ``"skip"`` (do nothing and carry on with the next statement).
    """

    module: str
    fingerprint: str
    action: str = "raise"
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.module, str) or not self.module:
            raise BlocklistError(f"rule module must be a non-empty string, got {self.module!r}")
        if len(self.module) > MAX_MODULE_LENGTH:
            raise BlocklistError(
                f"rule module must be at most {MAX_MODULE_LENGTH} characters, "
                f"got {len(self.module)}"
            )
        # A module name is echoed by `astblock check` and written to logs, so
        # it must be a real dotted name and not, say, text containing a newline
        # that forges a line of output. isidentifier() also rules out control
        # characters, spaces and empty components.
        if not all(part.isidentifier() for part in self.module.split(".")):
            raise BlocklistError(
                f"rule module must be a dotted module name, got {self.module!r}"
            )
        if not isinstance(self.fingerprint, str) or not _FINGERPRINT_RE.match(self.fingerprint):
            raise BlocklistError(
                f"rule fingerprint must be {FINGERPRINT_LENGTH} lowercase hex characters, "
                f"got {self.fingerprint!r}"
            )
        if self.action not in ACTIONS:
            raise BlocklistError(f"rule action must be one of {ACTIONS}, got {self.action!r}")
        if self.reason is None:
            return
        if not isinstance(self.reason, str):
            raise BlocklistError(f"rule reason must be a string, got {self.reason!r}")
        if len(self.reason) > MAX_REASON_LENGTH:
            raise BlocklistError(
                f"rule reason must be at most {MAX_REASON_LENGTH} characters, "
                f"got {len(self.reason)}"
            )
        found = _CONTROL_RE.search(self.reason)
        if found:
            raise BlocklistError(
                f"rule reason must not contain control characters, found "
                f"{found.group()!r} at position {found.start()}"
            )


class Blocklist:
    """A set of rules, indexed by module and fingerprint.

    ``strict`` makes a rule that matches no statement fatal at import time
    rather than a logged warning. See :class:`astblock.StaleRuleError`.
    """

    def __init__(self, rules: Iterable[Rule] = (), strict: bool = False) -> None:
        self._by_module: dict[str, dict[str, Rule]] = {}
        self.strict = strict
        for rule in rules:
            self.add(rule)

    def add(self, rule: Rule) -> None:
        self._by_module.setdefault(rule.module, {})[rule.fingerprint] = rule

    @property
    def modules(self) -> frozenset[str]:
        return frozenset(self._by_module)

    def rules_for(self, module: str) -> Mapping[str, Rule]:
        return dict(self._by_module.get(module, {}))

    def __iter__(self) -> Iterator[Rule]:
        for rules in self._by_module.values():
            yield from rules.values()

    def __len__(self) -> int:
        return sum(len(rules) for rules in self._by_module.values())

    def __repr__(self) -> str:
        strict = ", strict" if self.strict else ""
        return f"Blocklist({len(self)} rules in {len(self._by_module)} modules{strict})"

    # -- serialisation -------------------------------------------------

    @classmethod
    def from_dict(cls, data: object) -> "Blocklist":
        if not isinstance(data, dict):
            raise BlocklistError("blocklist must be a JSON object")
        unknown = set(data) - {"version", "rules", "strict"}
        if unknown:
            raise BlocklistError(f"unknown top-level keys: {sorted(unknown)}")
        if data.get("version", FILE_VERSION) != FILE_VERSION:
            raise BlocklistError(f"unsupported blocklist version {data.get('version')!r}")
        strict = data.get("strict", False)
        if not isinstance(strict, bool):
            raise BlocklistError(f"'strict' must be true or false, got {strict!r}")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise BlocklistError("'rules' must be a list")
        if len(raw_rules) > MAX_RULES:
            raise BlocklistError(
                f"blocklist has {len(raw_rules)} rules, more than the {MAX_RULES} allowed"
            )
        rules = []
        for position, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                raise BlocklistError(f"rule #{position} must be an object")
            unknown = set(raw) - _RULE_KEYS
            if unknown:
                raise BlocklistError(f"rule #{position} has unknown keys: {sorted(unknown)}")
            missing = {"module", "fingerprint"} - set(raw)
            if missing:
                raise BlocklistError(f"rule #{position} is missing: {sorted(missing)}")
            try:
                rules.append(Rule(**raw))
            except BlocklistError as exc:
                raise BlocklistError(f"rule #{position}: {exc}") from None
        return cls(rules, strict=strict)

    @classmethod
    def from_json(cls, text: str) -> "Blocklist":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise BlocklistError(f"invalid JSON: {exc}") from None
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "Blocklist":
        try:
            with open(path, encoding="utf-8") as handle:
                # fstat the open handle rather than the name, so the file that
                # is checked is the same one that is read.
                info = os.fstat(handle.fileno())
                _check_file_mode(path, info)
                if info.st_size > MAX_FILE_BYTES:
                    raise BlocklistError(
                        f"blocklist {os.fspath(path)!r} is {info.st_size} bytes, "
                        f"larger than the {MAX_FILE_BYTES} byte limit"
                    )
                text = handle.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            raise BlocklistError(f"cannot read blocklist {os.fspath(path)!r}: {exc}") from None
        if len(text) > MAX_FILE_BYTES:
            raise BlocklistError(
                f"blocklist {os.fspath(path)!r} is larger than the "
                f"{MAX_FILE_BYTES} byte limit"
            )
        return cls.from_json(text)

    def to_dict(self) -> dict:
        rules = []
        for rule in self:
            entry = asdict(rule)
            if entry["reason"] is None:
                del entry["reason"]
            rules.append(entry)
        data: dict = {"version": FILE_VERSION}
        if self.strict:
            data["strict"] = True
        data["rules"] = rules
        return data


def _check_file_mode(path: str | os.PathLike[str], info: os.stat_result) -> None:
    """Refuse a world-writable blocklist and warn about a group-writable one.

    Anyone who can write this file can disable any statement in the program,
    including an authorization check, so the file's permissions are part of
    the security boundary. Only meaningful on POSIX: the mode bits Windows
    reports are synthesised and say nothing about who can write the file.
    """
    if os.name != "posix":
        return
    mode = stat.S_IMODE(info.st_mode)
    if mode & stat.S_IWOTH:
        raise BlocklistError(
            f"blocklist {os.fspath(path)!r} is world-writable (mode {mode:04o}); "
            f"any user on this host could disable any statement in this program. "
            f"Run 'chmod o-w {os.fspath(path)}' before using it."
        )
    if mode & stat.S_IWGRP:
        logger.warning(
            "astblock: blocklist %s is group-writable (mode %04o), so any member of "
            "group %d can change which statements are blocked",
            os.fspath(path), mode, info.st_gid,
        )
    _check_directory_mode(path)


def _check_directory_mode(path: str | os.PathLike[str]) -> None:
    """Warn when the containing directory lets anyone replace the blocklist.

    A correctly-moded file in a world-writable directory without the sticky
    bit can simply be renamed away and replaced, so the permissions on the
    file alone do not settle the question. This warns rather than refuses,
    because a deploy that writes the file into a shared directory is a real
    pattern and the file itself is still the thing being read.
    """
    parent = os.path.dirname(os.path.abspath(os.fspath(path))) or os.curdir
    try:
        mode = stat.S_IMODE(os.stat(parent).st_mode)
    except OSError:
        return
    if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
        logger.warning(
            "astblock: directory %s is world-writable and not sticky (mode %04o), so "
            "any user on this host could replace the blocklist in it", parent, mode,
        )
