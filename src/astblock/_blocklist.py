"""Blocklist rules and their JSON file format.

Example file::

    {
      "version": 1,
      "rules": [
        {
          "module": "myapp.billing",
          "fingerprint": "3f9a0c1d2e4b5a67",
          "action": "skip",
          "reason": "INC-1234: duplicate charge email"
        }
      ]
    }
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Iterable, Iterator, Mapping

from ._errors import BlocklistError
from ._fingerprint import FINGERPRINT_LENGTH

ACTIONS = ("raise", "skip")
FILE_VERSION = 1

_FINGERPRINT_RE = re.compile(rf"^[0-9a-f]{{{FINGERPRINT_LENGTH}}}$")
_RULE_KEYS = {"module", "fingerprint", "action", "reason"}


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
        if not isinstance(self.fingerprint, str) or not _FINGERPRINT_RE.match(self.fingerprint):
            raise BlocklistError(
                f"rule fingerprint must be {FINGERPRINT_LENGTH} lowercase hex characters, "
                f"got {self.fingerprint!r}"
            )
        if self.action not in ACTIONS:
            raise BlocklistError(f"rule action must be one of {ACTIONS}, got {self.action!r}")
        if self.reason is not None and not isinstance(self.reason, str):
            raise BlocklistError(f"rule reason must be a string, got {self.reason!r}")


class Blocklist:
    """A set of rules, indexed by module and fingerprint."""

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self._by_module: dict[str, dict[str, Rule]] = {}
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
        return f"Blocklist({len(self)} rules in {len(self._by_module)} modules)"

    # -- serialisation -------------------------------------------------

    @classmethod
    def from_dict(cls, data: object) -> "Blocklist":
        if not isinstance(data, dict):
            raise BlocklistError("blocklist must be a JSON object")
        unknown = set(data) - {"version", "rules"}
        if unknown:
            raise BlocklistError(f"unknown top-level keys: {sorted(unknown)}")
        if data.get("version", FILE_VERSION) != FILE_VERSION:
            raise BlocklistError(f"unsupported blocklist version {data.get('version')!r}")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise BlocklistError("'rules' must be a list")
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
        return cls(rules)

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
                text = handle.read()
        except OSError as exc:
            raise BlocklistError(f"cannot read blocklist {os.fspath(path)!r}: {exc}") from None
        return cls.from_json(text)

    def to_dict(self) -> dict:
        rules = []
        for rule in self:
            entry = asdict(rule)
            if entry["reason"] is None:
                del entry["reason"]
            rules.append(entry)
        return {"version": FILE_VERSION, "rules": rules}
