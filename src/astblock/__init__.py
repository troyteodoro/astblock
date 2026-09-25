"""astblock: block individual statements from running, using an AST-fingerprint blocklist."""

from ._blocklist import ACTIONS, Blocklist, Rule
from ._errors import BlockedStatementError, BlocklistError
from ._fingerprint import Statement, find_statements, fingerprint_source
from ._runtime import hits, reset_hits
from ._transform import compile_with_blocklist

__version__ = "0.1.0"

__all__ = [
    "ACTIONS",
    "BlockedStatementError",
    "Blocklist",
    "BlocklistError",
    "Rule",
    "Statement",
    "compile_with_blocklist",
    "find_statements",
    "fingerprint_source",
    "hits",
    "reset_hits",
]
