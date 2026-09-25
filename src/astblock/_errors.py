"""Exception types raised by astblock."""

from __future__ import annotations


class BlocklistError(ValueError):
    """Raised when a blocklist is malformed or cannot be loaded."""


class StaleRuleError(BlocklistError):
    """Raised when a strict blocklist has a rule that matches no statement.

    A rule matches nothing when the code moved on since it was written. Under
    a strict blocklist that is fatal at import time: an operator asked for a
    statement to be blocked, and it is better to fail loudly than to run the
    statement they were trying to stop.
    """

    def __init__(self, module: str, fingerprints: list[str]) -> None:
        self.module = module
        self.fingerprints = fingerprints
        super().__init__(
            f"{len(fingerprints)} rule(s) for {module} matched no statement "
            f"(code changed since the rule was written?): {', '.join(fingerprints)}"
        )


class BlockedStatementError(RuntimeError):
    """Raised at runtime when execution reaches a statement blocked with action="raise"."""

    def __init__(self, fingerprint: str, reason: str | None = None) -> None:
        self.fingerprint = fingerprint
        self.reason = reason
        message = f"statement {fingerprint} is blocked by astblock"
        if reason:
            message += f" ({reason})"
        super().__init__(message)
