"""astblock: block individual statements from running, using an AST-fingerprint blocklist."""

from ._fingerprint import Statement, find_statements, fingerprint_source

__version__ = "0.1.0"

__all__ = [
    "Statement",
    "find_statements",
    "fingerprint_source",
]
