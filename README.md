# astblock

Switch off individual Python statements without editing or redeploying the code.

You write a small JSON blocklist naming statements by an AST fingerprint. When
the program starts with that blocklist, each blocked statement is rewritten at
import time so that it either **skips** (does nothing) or **raises**. Everything
not on the list is compiled exactly as normal.

The intended use is emergency mitigation: a third-party call that hangs, a
side effect that fires twice, a code path that corrupts data. It lets you turn
that one statement off with a config change and a restart, while the proper fix
goes through your normal release process.
