"""Exception types raised by astblock."""

from __future__ import annotations


class BlocklistError(ValueError):
    """Raised when a blocklist is malformed or cannot be loaded."""


class BlockedStatementError(RuntimeError):
    """Raised at runtime when execution reaches a statement blocked with action="raise"."""

    def __init__(self, fingerprint: str, reason: str | None = None) -> None:
        self.fingerprint = fingerprint
        self.reason = reason
        message = f"statement {fingerprint} is blocked by astblock"
        if reason:
            message += f" ({reason})"
        super().__init__(message)
