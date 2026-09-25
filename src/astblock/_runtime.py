"""Runtime side of a blocked statement.

Every blocked statement is rewritten into a call to :func:`blocked`, so that
hits are counted and logged and ``raise`` rules can raise. This module is
imported by rewritten code, so it must stay small and dependency-free.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter

from ._errors import BlockedStatementError

logger = logging.getLogger("astblock")

_hits: Counter[str] = Counter()
_lock = threading.Lock()


def blocked(fingerprint: str, action: str, reason: str | None) -> None:
    with _lock:
        _hits[fingerprint] += 1
        first = _hits[fingerprint] == 1
    # Log the first hit loudly and later hits quietly, so a blocked statement
    # inside a hot loop doesn't flood the logs.
    level = logging.WARNING if first else logging.DEBUG
    logger.log(level, "astblock: blocked statement %s reached (action=%s, reason=%s)",
               fingerprint, action, reason)
    if action == "raise":
        raise BlockedStatementError(fingerprint, reason)


def hits() -> dict[str, int]:
    """Return how many times each blocked statement has been reached."""
    with _lock:
        return dict(_hits)


def reset_hits() -> None:
    with _lock:
        _hits.clear()
